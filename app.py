from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import or_
# from dotenv import load_dotenv
import os
from flask_cors import CORS


# โหลด environment variables จากไฟล์ .env
# load_dotenv()


app = Flask(__name__)
CORS(app)  # อนุญาต Cross-Origin สำหรับทุก request


app.config['JWT_SECRET_KEY'] = 'glass'  # เปลี่ยนให้ปลอดภัย

# โหลดค่า DATABASE_URL จาก Environment Variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')


db = SQLAlchemy(app)
jwt = JWTManager(app)

# Model for storing location data
class gps_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# เพิ่ม Model สำหรับผู้ใช้
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' หรือ 'user'

    # กำหนดความสัมพันธ์กับ gps_data
    gps_records = db.relationship('gps_data', backref='user', cascade="all, delete", lazy=True)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    print('data is', data)
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role is 'user'

    # ตรวจสอบว่า email หรือ username มีอยู่แล้วในฐานข้อมูล
    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()

    if existing_user:
        return jsonify({"message": "Email หรือ Username นี้มีผู้ใช้งานแล้ว"}), 400

    # แฮชรหัสผ่านก่อนเก็บ
    # ใช้ 'pbkdf2:sha256' แทน 'sha256'
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User( username=username, email=email, password=hashed_password, role=role)

    try:
        db.session.add(new_user)
        db.session.commit()
        print("New user added to database successfully.")
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500




@app.route('/api/admin', methods=['GET'])
# @jwt_required()  # ใช้ JWT ในการตรวจสอบว่าเป็นผู้ที่ล็อกอิน
def admin():
    # ดึงข้อมูลของผู้ใช้ที่ล็อกอินจาก JWT Token
    current_user = get_jwt_identity()
    
    # ตรวจสอบว่า role ของผู้ใช้เป็น admin หรือไม่
    if current_user["role"] != "admin":
        return jsonify({"message": "Access denied. Admins only."}), 403

    # ส่งข้อมูลเกี่ยวกับผู้ใช้ที่ล็อกอิน
    return jsonify({
        "message": "Welcome to the admin page",
        "username": current_user["username"]
    }), 200


# Login Route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    print('Data is: ', data)
    identifier = data.get('identifier')  # รับทั้ง username หรือ email
    password = data.get('password')

    # ค้นหาผู้ใช้โดย username หรือ email
    user = User.query.filter(or_(User.email == identifier, User.username == identifier)).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username/email or password"}), 401

    # สร้าง JWT Token พร้อม Role
    access_token = create_access_token(identity={"id": user.id, "role": user.role, "username": user.username})
    
    print(access_token)
    
    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "role": user.role,
        "username": user.username
    }), 200
    


# API endpoint to receive data
@app.route('/api/locations', methods=['POST'])
def receive_location():
    data = request.json
    timestamp = datetime.utcnow()


    location = gps_data(
        device_id=data['device_id'],
        latitude=data['latitude'],
        longitude=data['longitude'],
        timestamp=timestamp,
        user_id=data['user_id'],
    )
    db.session.add(location)
    db.session.commit()
    return jsonify({"message": "Data received"}), 200


# API endpoint to get the latest location by gps_id
@app.route('/api/Getlocations/<int:gps_id>', methods=['GET'])
def get_latest_location_by_id(gps_id):
    
    latest_location = (
        gps_data.query.filter_by(user_id=gps_id)
        .order_by(gps_data.timestamp.desc())
        .first()
    )

    if not latest_location:
        return jsonify({"message": "No data found for this GPS ID"}), 404

    # Query user information based on device_id or user_id (adjust based on your schema)
    user = User.query.filter_by(id=latest_location.user_id).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    print(user)
    # Check role
    if user.role != 'user':
        return jsonify({
            "message": "Access denied for this role",
            "role": user.role,  # เพิ่ม role เพื่อตรวจสอบฝั่ง Frontend
            "username": user.username  # เพิ่ม username เพื่อตรวจสอบได้ชัดเจนขึ้น
        }), 403

    print(user)

    # Prepare response
    location_data = {
        "latitude": latest_location.latitude,
        "longitude": latest_location.longitude,
        "user_id": user.id,
        "username": user.username,  # ส่ง username ไปด้วย
        "role": user.role,
        "timestamp": latest_location.timestamp,
    }
    
    print(location_data)

    return jsonify(location_data), 200

@app.route('/api/accounts', methods=['GET'])
# @jwt_required()
def get_accounts():
    try:
        # current_user = get_jwt_identity()  # ดึงข้อมูลผู้ใช้ปัจจุบันจาก JWT
        users = User.query.all()  # ดึงข้อมูลทั้งหมดจากตาราง User

        if not users:
            # ถ้าไม่มีผู้ใช้ในฐานข้อมูล
            return jsonify({
                "message": "No users found."
            }), 404

        # สร้างรายการผู้ใช้
        result = [{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "password": user.password,
            "role": user.role
        } for user in users]

        # ส่งผลลัพธ์กลับ
        return jsonify({
            # "message": "Successfully retrieved users.",
            # "current_user": current_user,
            "accounts": result
        }), 200

    except Exception as e:
        # หากเกิดข้อผิดพลาดในการดึงข้อมูล
        return jsonify({
            "message": "Failed to retrieve users.",
            "error": str(e)
        }), 500

@app.route('/api/accounts/<int:id>', methods=['PUT'])
# @jwt_required()  # หากใช้ JWT, ยืนยันตัวตนผู้ใช้
def update_account(id):
    try:
        # ดึงข้อมูลที่ส่งมาจากคำขอ (Request)
        data = request.get_json()

        # ค้นหาผู้ใช้ที่ต้องการอัปเดตจากฐานข้อมูล
        user = User.query.get(id)

        if not user:
            return jsonify({
                "message": "User not found."
            }), 404

        # อัปเดตข้อมูลผู้ใช้
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.password = data.get('password', user.password)
        user.role = data.get('role', user.role)

        # บันทึกการเปลี่ยนแปลง
        db.session.commit()

        return jsonify({
            "message": "User updated successfully.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Failed to update user.",
            "error": str(e)
        }), 500


@app.route('/api/accounts/<int:id>', methods=['DELETE'])
# @jwt_required()  # หากใช้ JWT, ยืนยันตัวตนผู้ใช้
def delete_account(id):
    try:
        # ค้นหาผู้ใช้ที่ต้องการลบจากฐานข้อมูล
        user = User.query.get(id)

        if not user:
            return jsonify({
                "message": "User not found."
            }), 404

        # ลบข้อมูลผู้ใช้
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            "message": "User deleted successfully."
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Failed to delete user.",
            "error": str(e)
        }), 500


from werkzeug.security import generate_password_hash

@app.route('/api/accounts', methods=['POST'])
# @jwt_required()  # ใช้หากต้องการตรวจสอบ JWT
def add_account():
    try:
        # ดึงข้อมูลจาก request body
        data = request.get_json()

        # ตรวจสอบว่าได้รับข้อมูลครบถ้วน
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "message": f"Missing required field: {field}"
                }), 400

        # ตรวจสอบว่ามีผู้ใช้งานอยู่แล้วหรือไม่
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({
                "message": "User with this email already exists."
            }), 409

        # แฮชรหัสผ่านก่อนบันทึก
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

        # สร้างผู้ใช้ใหม่
        new_user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,  # เก็บรหัสผ่านที่แฮชแล้ว
            role=data['role']
        )

        # เพิ่มผู้ใช้ในฐานข้อมูล
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "message": "User successfully added.",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "role": new_user.role
            }
        }), 201

    except Exception as e:
        # หากเกิดข้อผิดพลาด
        db.session.rollback()  # ย้อนกลับการเปลี่ยนแปลงในฐานข้อมูล
        return jsonify({
            "message": "Failed to add user.",
            "error": str(e)
        }), 500



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
