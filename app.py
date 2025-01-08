from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import or_
from dotenv import load_dotenv
import os
from flask_cors import CORS
from datetime import timedelta

# โหลด environment variables จากไฟล์ .env
# load_dotenv()


app = Flask(__name__)
CORS(app)  # อนุญาต Cross-Origin สำหรับทุก request


app.config['JWT_SECRET_KEY'] = 'glass'  # เปลี่ยนให้ปลอดภัย

# โหลดค่า DATABASE_URL จาก Environment Variable
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://blind-glasses-data_owner:zE8HmV4nIKiL@ep-lingering-bread-a17i0srx.ap-southeast-1.aws.neon.tech/blind-glasses-data?sslmode=require"


db = SQLAlchemy(app)
jwt = JWTManager(app)

class UserDeviceAccess(db.Model):
    __tablename__ = 'user_device_access'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_id = db.Column(db.String, nullable=False)

    user = db.relationship('User', backref='device_access')


# Model for storing location data
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' หรือ 'user'

    # กำหนดความสัมพันธ์กับ gps_data
    gps_records = db.relationship('gps_data', backref='user', cascade="all, delete", lazy=True)

class gps_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    

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
@jwt_required()  # ใช้ JWT ในการตรวจสอบว่าเป็นผู้ที่ล็อกอิน
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
    identifier = data.get('identifier')
    password = data.get('password')

    # ค้นหาผู้ใช้
    user = User.query.filter(or_(User.email == identifier, User.username == identifier)).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username/email or password"}), 401

# สร้าง Token พร้อมตั้งค่า expiration
    access_token = create_access_token(
                identity={"id": user.id, "role": user.role, "username": user.username}, 
                expires_delta=timedelta(hours=1)  # Token จะหมดอายุใน 1 ชั่วโมง
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "role": user.role,
        "username": user.username,
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
@app.route('/api/Getlocations/<string:device_id>', methods=['GET'])
@jwt_required()  # เพิ่ม decorator นี้
def get_latest_location_by_device_id(device_id):
    # ดึง user ที่กำลังทำการร้องขอ (สมมติว่าคุณใช้ token-based authentication)
    user_id = get_jwt_identity()  # ฟังก์ชันนี้ควรดึง user_id จาก token

    print(user_id)
    
    # ตรวจสอบว่า user มีสิทธิ์เข้าถึง device_id นี้หรือไม่
    has_access = UserDeviceAccess.query.filter_by(user_id=user_id, device_id=device_id).first()
    if not has_access:
        return jsonify({"message": "You do not have access to this device ID"}), 403

    # ดึงตำแหน่งล่าสุดจาก gps_data
    latest_location = (
        gps_data.query.filter_by(device_id=device_id)
        .order_by(gps_data.timestamp.desc())
        .first()
    )

    if not latest_location:
        return jsonify({"message": "No data found for this device ID"}), 404

    # Prepare response
    location_data = {
        "latitude": latest_location.latitude,
        "longitude": latest_location.longitude,
        "timestamp": latest_location.timestamp,
    }

    return jsonify(location_data), 200


@app.route('/api/accounts', methods=['GET'])
@jwt_required()
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
@jwt_required()  # หากใช้ JWT, ยืนยันตัวตนผู้ใช้
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
@jwt_required()  # หากใช้ JWT, ยืนยันตัวตนผู้ใช้
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



@app.route('/api/accounts', methods=['POST'])
@jwt_required()  # ใช้หากต้องการตรวจสอบ JWT
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


# หน้า TABLE For ADMIN
@app.route('/api/glasses-data', methods=['GET'])
def get_glasses_data():
    try:
        # ดึงข้อมูลล่าสุดของแต่ละ user จาก gps_data
        subquery = db.session.query(
            gps_data.user_id,
            db.func.max(gps_data.timestamp).label('max_timestamp')
        ).group_by(gps_data.user_id).subquery()

        # Join กับตาราง users และข้อมูล GPS ล่าสุด
        results = db.session.query(
            User.id,
            User.username,
            User.email,
            gps_data.latitude,
            gps_data.longitude,
            # ในที่นี้สมมติว่าใช้ device_id เป็นค่าแบตเตอรี่ (คุณอาจต้องปรับตามโครงสร้างจริง)
            gps_data.device_id.label('battery_level')
        ).join(
            subquery,
            User.id == subquery.c.user_id
        ).join(
            gps_data,
            db.and_(
                gps_data.user_id == subquery.c.user_id,
                gps_data.timestamp == subquery.c.max_timestamp
            )
        ).all()

        # แปลงผลลัพธ์เป็นรูปแบบที่ต้องการ
        glasses_data = []
        for result in results:
            glasses_data.append({
                'id': result.id,
                'username': result.username,
                'email': result.email,
                # แปลง device_id เป็นค่าแบตเตอรี่ (ตัวอย่าง)
                'battery': int(float(result.battery_level)) if result.battery_level.replace('.', '').isdigit() else 0,
                'location': f'Lat: {result.latitude}, Long: {result.longitude}'
            })

        return jsonify({
            'status': 'success',
            'data': glasses_data
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


if __name__ == "__main__":
    app.run()
