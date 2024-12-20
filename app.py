from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # อนุญาต Cross-Origin สำหรับทุก request


app.config['JWT_SECRET_KEY'] = 'glass'  # เปลี่ยนให้ปลอดภัย

# โหลดค่า DATABASE_URL จาก Environment Variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# ตรวจสอบว่ามีการตั้งค่า DATABASE_URL หรือไม่
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("DATABASE_URL environment variable not set")

# Initialize SQLAlchemy
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
    username = db.Column(db.String(255), unique = True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' หรือ 'user'


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



# Login Route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    print('Data is: ', data)
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid email or password"}), 401

    # สร้าง JWT Token พร้อม Role
    access_token = create_access_token(identity={"id": user.id, "role": user.role})
    
    print(access_token)
    
    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "role": user.role
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



if __name__ == "__main__":
    app.run()
