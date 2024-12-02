from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta

# Ініціалізація додатку
app = Flask(__name__)

# Налаштування бази даних
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'todo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Налаштування JWT
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # ВАЖЛИВО: Змініть на унікальний секретний ключ
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

# Ініціалізація розширень
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)

# Модель користувача
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

# Модель завдання (оновлена з полем user_id)
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, title, description, user_id, completed=False):
        self.title = title
        self.description = description
        self.user_id = user_id
        self.completed = completed

# Схеми серіалізації
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        exclude = ('password',)

class TodoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Todo
        load_instance = True

# Ініціалізація схем
user_schema = UserSchema()
users_schema = UserSchema(many=True)
todo_schema = TodoSchema()
todos_schema = TodoSchema(many=True)

# Список відкликаних токенів (у реальному додатку використовуйте Redis або базу даних)
jwt_blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in jwt_blacklist

# Маршрути аутентифікації
@app.route('/register', methods=['POST'])
def register():
    """Реєстрація нового користувача"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Перевірка наявності username та паролю
    if not username or not password:
        return jsonify({'error': 'Username та пароль є обов\'язковими'}), 400
    
    # Перевірка чи існує вже користувач
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Користувач з таким username вже існує'}), 400
    
    # Створення нового користувача
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    
    return user_schema.jsonify(new_user), 201

@app.route('/login', methods=['POST'])
def login():
    """Вхід користувача та генерація JWT токену"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Знаходження користувача
    user = User.query.filter_by(username=username).first()
    
    # Перевірка паролю
    if user and check_password_hash(user.password, password):
        # Створення access токену
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    
    return jsonify({'error': 'Невірний username або пароль'}), 401

@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    """Вихід користувача та відкликання токену"""
    jti = get_jwt()['jti']
    jwt_blacklist.add(jti)
    return jsonify({'message': 'Успішний вихід'}), 200

# Захищені маршрути для роботи з завданнями
@app.route('/todo', methods=['POST'])
@jwt_required()
def add_todo():
    """Додати нове завдання"""
    current_user_id = get_jwt_identity()
    
    title = request.json.get('title')
    description = request.json.get('description', '')
    
    if not title:
        return jsonify({'error': 'Назва завдання є обов\'язковою'}), 400
    
    new_todo = Todo(title=title, description=description, user_id=current_user_id)
    
    db.session.add(new_todo)
    db.session.commit()
    
    return todo_schema.jsonify(new_todo), 201

@app.route('/todos', methods=['GET'])
@jwt_required()
def get_todos():
    """Отримати список завдань поточного користувача"""
    current_user_id = get_jwt_identity()
    todos = Todo.query.filter_by(user_id=current_user_id).all()
    return todos_schema.jsonify(todos)

@app.route('/todo/<int:todo_id>', methods=['GET'])
@jwt_required()
def get_todo(todo_id):
    """Отримати конкретне завдання за ID"""
    current_user_id = get_jwt_identity()
    
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user_id).first_or_404()
    return todo_schema.jsonify(todo)

@app.route('/todo/<int:todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    """Оновити завдання"""
    current_user_id = get_jwt_identity()
    
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user_id).first_or_404()
    
    todo.title = request.json.get('title', todo.title)
    todo.description = request.json.get('description', todo.description)
    todo.completed = request.json.get('completed', todo.completed)
    
    db.session.commit()
    
    return todo_schema.jsonify(todo)

@app.route('/todo/<int:todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    """Видалити завдання"""
    current_user_id = get_jwt_identity()
    
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user_id).first_or_404()
    
    db.session.delete(todo)
    db.session.commit()
    
    return jsonify({'message': 'Завдання видалено'}), 200

# Додаткові захищені маршрути
@app.route('/todos/completed', methods=['GET'])
@jwt_required()
def get_completed_todos():
    """Отримати список завершених завдань поточного користувача"""
    current_user_id = get_jwt_identity()
    completed_todos = Todo.query.filter_by(user_id=current_user_id, completed=True).all()
    return todos_schema.jsonify(completed_todos)

@app.route('/todos/pending', methods=['GET'])
@jwt_required()
def get_pending_todos():
    """Отримати список незавершених завдань поточного користувача"""
    current_user_id = get_jwt_identity()
    pending_todos = Todo.query.filter_by(user_id=current_user_id, completed=False).all()
    return todos_schema.jsonify(pending_todos)

# Обробка помилок
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Не знайдено', 'message': str(error)}), 404

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Помилковий запит', 'message': str(error)}), 400

# Створення таблиць бази даних
with app.app_context():
    db.create_all()

# Приклади використання API:
'''
# Реєстрація
curl -X POST http://localhost:5000/register 
     -H "Content-Type: application/json" 
     -d '{"username":"user1","password":"password123"}'

# Вхід (отримання токену)
curl -X POST http://localhost:5000/login 
     -H "Content-Type: application/json" 
     -d '{"username":"user1","password":"password123"}'

# Додати завдання (з токеном)
curl -X POST http://localhost:5000/todo 
     -H "Content-Type: application/json" 
     -H "Authorization: Bearer {JWT_TOKEN}" 
     -d '{"title":"Купити продукти","description":"Молоко, хліб, яйця"}'

# Вихід (відкликання токену)
curl -X DELETE http://localhost:5000/logout 
     -H "Authorization: Bearer {JWT_TOKEN}"
'''

if __name__ == '__main__':
    app.run(debug=True)
