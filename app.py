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
import json

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # ✅ เพิ่ม created_at

    user = db.relationship('User', backref='device_access')


# Model for storing location data
# Model สำหรับผู้ใช้
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' หรือ 'user'

    # ความสัมพันธ์กับ gps_data (ผู้ใช้แต่ละคนสามารถมีหลายอุปกรณ์)
    gps_records = db.relationship('gps_data', backref='user', cascade="all, delete", lazy=True)

# Model สำหรับพิกัด GPS
class gps_data(db.Model):
    __tablename__ = 'gps_data'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # ใช้ id เป็น PRIMARY KEY
    device_id = db.Column(db.String(50), nullable=False, index=True)  # เพิ่ม index เพื่อค้นหาเร็วขึ้น
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)  # เพิ่ม index

    # เพิ่ม unique index เพื่อให้แต่ละอุปกรณ์มีเพียง 1 ข้อมูลล่าสุด ถ้าต้องการบันทึกเฉพาะค่าล่าสุด
    __table_args__ = (
        db.Index('idx_device_timestamp', device_id, timestamp.desc()),  # Index สำหรับการ query ค่าล่าสุด
    )

#Model Status device
class DeviceStatus(db.Model):
    __tablename__ = "device_status"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    gps_id = db.Column(db.Integer, db.ForeignKey("gps_data.id"), nullable=False)  # เชื่อมโยงกับ gps_data.id
    temperature = db.Column(db.Float, nullable=False)
    battery_level = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # การเชื่อมโยงกลับไปยัง gps_data
    gps_data = db.relationship("gps_data", backref=db.backref("device_status", uselist=False))




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

    # แปลงข้อมูล identity เป็น JSON String
    access_token = create_access_token(
        identity=json.dumps({"id": user.id, "role": user.role, "username": user.username}),
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
    try:
        data = request.json
        if not all(key in data for key in ('user_id', 'device_id', 'latitude', 'longitude', 'temperature', 'battery_level')):
            return jsonify({"message": "Missing required fields"}), 400

        device_id = data["device_id"]
        user_id = data["user_id"]
        latitude = data["latitude"]
        longitude = data["longitude"]
        temperature = data["temperature"]
        battery_level = data["battery_level"]
        timestamp = datetime.utcnow()

        # UPSERT: ถ้ามี device_id อยู่แล้วให้ update ตำแหน่งใหม่ใน gps_data
        gps_entry = gps_data.query.filter_by(device_id=device_id).first()
        if gps_entry:
            gps_entry.latitude = latitude
            gps_entry.longitude = longitude
            gps_entry.timestamp = timestamp
        else:
            # user_id ในทีนี้สำหรับการเพิ่มในตาราง gps_data (ถ้าเกิดว่าเป็นข้อมูล device_id ใหม่ใน gps_data)
            gps_entry = gps_data(device_id=device_id, user_id=user_id, latitude=latitude, longitude=longitude, timestamp=timestamp)
            db.session.add(gps_entry)

        # UPSERT: ถ้ามี gps_id อยู่แล้วให้ update ค่าของ temperature และ battery ใน DeviceStatus
        device_status = DeviceStatus.query.filter_by(gps_id=gps_entry.id).first()
        if device_status:
            device_status.temperature = temperature
            device_status.battery_level = battery_level
            device_status.timestamp = timestamp
        else:
            device_status = DeviceStatus(gps_id=gps_entry.id, temperature=temperature, battery_level=battery_level, timestamp=timestamp)
            db.session.add(device_status)

        db.session.commit()
        return jsonify({"message": "GPS data and Device Status updated successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500




@app.route('/api/Getlocations/<string:device_id>', methods=['GET'])
@jwt_required()
def get_latest_location_by_device_id(device_id):
    try:
        # Decode JWT identity
        identity = json.loads(get_jwt_identity())
        user_id = identity.get("id")  # ดึง user_id จาก identity

        # ตรวจสอบสิทธิ์ของ user กับ device_id
        access = UserDeviceAccess.query.filter_by(user_id=user_id, device_id=device_id).first()
        if not access:
            return jsonify({"message": "You do not have access to this device ID"}), 403

        # ดึง role ของ user
        user_role = access.user.role

        # ดึงตำแหน่งล่าสุดจาก gps_data
        latest_location = gps_data.query.filter_by(device_id=device_id).order_by(gps_data.timestamp.desc()).first()

        if not latest_location:
            return jsonify({"message": "No data found for this device ID"}), 404

        # Prepare response
        location_data = {
            "device_id": device_id,
            "latitude": latest_location.latitude,
            "longitude": latest_location.longitude,
            "timestamp": latest_location.timestamp.isoformat(),  # แปลง timestamp ให้ JSON อ่านได้
            "role": user_role,
        }

        return jsonify(location_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



## API For Who you can search
@app.route('/api/GetAccessibleDevices', methods=['GET'])
@jwt_required()
def get_accessible_devices():
    # Decode JWT identity
    identity = json.loads(get_jwt_identity())
    user_id = identity.get("id")  # ดึง user_id จาก JWT identity

    # ดึง device_id ทั้งหมดที่ user_id นี้สามารถเข้าถึงได้
    devices = UserDeviceAccess.query.filter_by(user_id=user_id).all()

    if not devices:
        return jsonify({"device_ids": []}), 200

    # สร้าง list ของ device_id
    device_ids = [device.device_id for device in devices]

    return jsonify({"device_ids": device_ids}), 200



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
@jwt_required()
def update_account(id):
    try:
        data = request.get_json()
        user = User.query.get(id)

        if not user:
            return jsonify({"message": "User not found."}), 404

        # อัปเดตข้อมูลทั่วไป
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)

        # ถ้ามีการส่ง password ใหม่มา ให้เข้ารหัสก่อนบันทึก
        if 'password' in data and data['password']:
            user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')

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
        db.session.rollback()
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


@app.route('/api/glasses-data', methods=['GET'])
def get_glasses_data():
    try:
        # ดึง GPS ล่าสุดของแต่ละ user
        subquery_gps = db.session.query(
            gps_data.user_id,
            db.func.max(gps_data.timestamp).label('max_timestamp')
        ).group_by(gps_data.user_id).subquery()

        # ดึง DeviceStatus ล่าสุดของแต่ละ GPS
        subquery_device = db.session.query(
            DeviceStatus.gps_id,
            db.func.max(DeviceStatus.timestamp).label('max_device_timestamp')
        ).group_by(DeviceStatus.gps_id).subquery()

        # Query ข้อมูล Users + GPS + DeviceStatus (เฉพาะอันล่าสุด)
        results = db.session.query(
            User.id,
            User.username,
            User.email,
            gps_data.latitude,
            gps_data.longitude,
            DeviceStatus.battery_level,
            DeviceStatus.temperature
        ).join(subquery_gps, User.id == subquery_gps.c.user_id) \
         .join(gps_data, db.and_(
             gps_data.user_id == subquery_gps.c.user_id,
             gps_data.timestamp == subquery_gps.c.max_timestamp
         )) \
         .outerjoin(subquery_device, gps_data.id == subquery_device.c.gps_id) \
         .outerjoin(DeviceStatus, db.and_(
             DeviceStatus.gps_id == gps_data.id,
             DeviceStatus.timestamp == subquery_device.c.max_device_timestamp
         )) \
         .order_by(User.id) \
         .all()

        # แปลงข้อมูลเป็น JSON
        glasses_data = [{
            'id': result.id,
            'username': result.username,
            'email': result.email,
            'battery': result.battery_level or 0,  # กำหนดค่าเริ่มต้น
            'temperature': result.temperature or 0.0,
            'latitude': result.latitude,
            'longitude': result.longitude
        } for result in results]

        return jsonify({'status': 'success', 'data': glasses_data}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/api/gps-ids', methods=['GET'])
def get_all_gps_ids():
    try:
        # ดึง gps_id และ device_id ทั้งหมดจากฐานข้อมูล
        gps_ids = db.session.query(DeviceStatus.gps_id, gps_data.device_id).join(
            gps_data, gps_data.id == DeviceStatus.gps_id
        ).distinct().all()

        if not gps_ids:
            return jsonify({'status': 'error', 'message': 'No GPS IDs found'}), 404

        # แปลงข้อมูลให้เป็น list ของ dicts
        gps_ids_list = [{'gps_id': gps_id[0], 'device_id': gps_id[1]} for gps_id in gps_ids]

        return jsonify({'status': 'success', 'gps_ids': gps_ids_list}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/api/gps-ids/data/<int:gps_id>', methods=['GET'])
def get_glasses_data_by_id(gps_id):
    try:
        # ดึงข้อมูลทั้งหมดของ GPS ID ที่ตรงกับ gps_id ที่ส่งมา
        records = db.session.query(
            gps_data.id,
            gps_data.device_id,
            DeviceStatus.gps_id,
            DeviceStatus.battery_level,
            DeviceStatus.temperature,
            DeviceStatus.timestamp
        ).join(
            DeviceStatus, DeviceStatus.gps_id == gps_data.id  # เชื่อมโยง gps_id
        ).filter(
            DeviceStatus.gps_id == gps_id  # กรองให้ gps_id ตรง
        ).order_by(DeviceStatus.timestamp.desc()).all()

        if not records:
            return jsonify({'status': 'error', 'message': 'GPS ID not found'}), 404

        # จัดรูปแบบข้อมูล
        data = {
            'gps_id': gps_id,
            'latest_record': {
                'device_id': records[0].device_id,  # ใช้ device_id จาก record ล่าสุด
                'battery_level': records[0].battery_level,
                'temperature': records[0].temperature,
                'timestamp': records[0].timestamp
            },
            'history': [
                {
                    'device_id': rec.device_id,  # ใช้ device_id จาก record
                    'battery_level': rec.battery_level,
                    'temperature': rec.temperature,
                    'timestamp': rec.timestamp
                }
                for rec in records[1:]  # ข้าม record ล่าสุด
            ]
        }

        return jsonify({'status': 'success', 'data': data}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



        # ดึง data สำหรับหน้า device
@app.route('/api/devices-data', methods=['GET'])
def get_devices_data():
    try:
        # Query ยังคงเหมือนเดิม
        results = db.session.query(
            UserDeviceAccess.id,
            UserDeviceAccess.user_id,
            UserDeviceAccess.device_id,
            UserDeviceAccess.created_at,
            User.username,
            User.email
        ).join(User, UserDeviceAccess.user_id == User.id) \
         .order_by(UserDeviceAccess.id) \
         .distinct()  \
         .all()

        devices_data = []
        seen = set()

        for result in results:
            key = (result.user_id, result.device_id)
            if key not in seen:
                seen.add(key)
                # แก้การ format วันที่ตรงนี้
                formatted_date = result.created_at.strftime('%d/%m/%Y %H:%M:%S')
                devices_data.append({
                    'id': result.id,
                    'user_id': result.user_id,
                    'device_id': result.device_id,
                    'created_at': formatted_date,  # ส่งวันที่ที่ format แล้ว
                    'username': result.username,
                    'email': result.email
                })

        return jsonify({'status': 'success', 'data': devices_data}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
        

@app.route('/api/devices', methods=['POST'])
def add_device():
        data = request.json  # รับข้อมูล JSON จาก client

        # ดึงข้อมูลจาก JSON
        user_id = data.get('userId')
        device_id = data.get('deviceId')

        # ตรวจสอบว่ามีข้อมูลครบหรือไม่
        if user_id and device_id:
            # ตรวจสอบว่า user_id และ device_id ซ้ำกันในฐานข้อมูลหรือไม่
            existing_access = UserDeviceAccess.query.filter_by(user_id=user_id, device_id=device_id).first()

            if existing_access:
                # ถ้ามีข้อมูลซ้ำ
                return jsonify({'status': 'error', 'message': 'User ID and Device ID combination already exists'}), 400
            else:
                # ถ้าไม่มีข้อมูลซ้ำ
                new_access = UserDeviceAccess(user_id=user_id, device_id=device_id)
                db.session.add(new_access)
                db.session.commit()

                # บันทึกลงฐานข้อมูล (สมมติว่า print แทน)
                print(f"User ID: {user_id} granted access to Device ID: {device_id} in user_device_access table.")
                return jsonify({'status': 'success', 'message': 'Device access granted'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400


@app.route('/api/devices/<int:access_id>', methods=['DELETE'])
def delete_device_access(access_id):
        try:
            # ค้นหาข้อมูลจาก id
            device_access = UserDeviceAccess.query.get(access_id)
            
            # ถ้าไม่พบข้อมูล
            if not device_access:
                return jsonify({
                    'status': 'error',
                    'message': 'Device access record not found'
                }), 404
                
            # เก็บข้อมูลไว้แสดงใน log
            user_id = device_access.user_id
            device_id = device_access.device_id
            
            # ลบข้อมูล
            db.session.delete(device_access)
            db.session.commit()
            
            # บันทึก log
            print(f"Deleted access - User ID: {user_id}, Device ID: {device_id}")
            
            return jsonify({
                'status': 'success',
                'message': 'Device access deleted successfully'
            }), 200
            
        except Exception as e:
            # ถ้าเกิดข้อผิดพลาด rollback การทำงาน
            db.session.rollback()
            return jsonify({
                'status': 'error',
                'message': f'Failed to delete device access: {str(e)}'
            }), 500


if __name__ == "__main__":
    app.run()
