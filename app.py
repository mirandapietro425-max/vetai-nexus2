@app.route('/api/pets', methods=['POST'])
@login_required
def create_pet():
    try:
        data = request.json
        new_pet = Pet(
            user_id=session['user_id'],
            name=data['name'],
            breed=data.get('breed', 'Raça indefinida'),
            type=data.get('type', 'Cachorro'),
            weight=data.get('weight', 0),
            photo_url=data.get('photo_url')
        )
        db_session.add(new_pet)
        db_session.commit()
        return jsonify({"success": True, "pet_id": new_pet.id})
    except Exception as e:
        db_session.rollback()
        print(f"❌ Erro ao criar pet: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/pets/<int:pet_id>', methods=['PUT'])
@login_required
def update_pet(pet_id):
    """Atualizar informações do pet"""
    try:
        data = request.json
        pet = db_session.query(Pet).filter_by(id=pet_id, user_id=session['user_id']).first()
        
        if not pet:
            return jsonify({"error": "Pet não encontrado"}), 404
        
        if 'weight' in data:
            pet.weight = data['weight']
        if 'breed' in data:
            pet.breed = data['breed']
        if 'name' in data:
            pet.name = data['name']
        if 'type' in data:
            pet.type = data['type']
            
        db_session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/pets/<int:pet_id>', methods=['DELETE'])
@login_required
def delete_pet(pet_id):
    """Deletar pet"""
    try:
        pet = db_session.query(Pet).filter_by(id=pet_id, user_id=session['user_id']).first()
        
        if not pet:
            return jsonify({"error": "Pet não encontrado"}), 404
        
        db_session.delete(pet)
        db_session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
        import os
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import requests
import stripe

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret-key-change-me")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
CORS(app, supports_credentials=True)

# Configurações
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL")

if not GEMINI_API_KEY:
    print("❌ ERRO CRÍTICO: GEMINI_API_KEY não configurada!")
else:
    print(f"✅ GEMINI_API_KEY configurada: {GEMINI_API_KEY[:10]}...")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    print("⚠️ AVISO: STRIPE_SECRET_KEY não configurada!")

# Configuração PostgreSQL
if not DATABASE_URL:
    print("❌ ERRO: DATABASE_URL não configurada!")
    DATABASE_URL = "sqlite:///vetai.db"
else:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
db_session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

FREE_POINTS = int(os.environ.get("FREE_POINTS", 50))
POINTS_PER_AI_CALL = int(os.environ.get("POINTS_PER_AI_CALL", 5))

# ========== DATABASE MODELS ==========

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    name = Column(String(255))
    is_premium = Column(Boolean, default=False)
    points = Column(Integer, default=50)
    stripe_customer_id = Column(String(255))
    subscription_id = Column(String(255))
    subscription_end = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    pets = relationship("Pet", back_populates="user", cascade="all, delete-orphan")
    usage_history = relationship("UsageHistory", back_populates="user", cascade="all, delete-orphan")

class Pet(Base):
    __tablename__ = 'pets'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(255), nullable=False)
    breed = Column(String(255))
    type = Column(String(100))
    weight = Column(Float)
    photo_url = Column(Text)  # MUDADO: Text ao invés de String(500)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="pets")
    meals = relationship("Meal", back_populates="pet", cascade="all, delete-orphan")
    vaccines = relationship("Vaccine", back_populates="pet", cascade="all, delete-orphan")

class Meal(Base):
    __tablename__ = 'meals'
    id = Column(Integer, primary_key=True)
    pet_id = Column(Integer, ForeignKey('pets.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    pet = relationship("Pet", back_populates="meals")

class Vaccine(Base):
    __tablename__ = 'vaccines'
    id = Column(Integer, primary_key=True)
    pet_id = Column(Integer, ForeignKey('pets.id'), nullable=False)
    name = Column(String(255), nullable=False)
    scheduled_date = Column(DateTime)
    applied_date = Column(DateTime)
    is_applied = Column(Boolean, default=False)
    
    pet = relationship("Pet", back_populates="vaccines")

class UsageHistory(Base):
    __tablename__ = 'usage_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(String(255), nullable=False)
    points_used = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="usage_history")

def init_db():
    Base.metadata.create_all(engine)
    print("✅ Database initialized with PostgreSQL")

init_db()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

# ========== DECORATORS ==========

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Não autenticado"}), 401
        return f(*args, **kwargs)
    return decorated_function

def check_points(points_needed):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"error": "Não autenticado"}), 401
            
            user = db_session.query(User).filter_by(id=user_id).first()
            
            if not user:
                return jsonify({"error": "Usuário não encontrado"}), 404
            
            if user.is_premium:
                return f(*args, **kwargs)
            
            if user.points < points_needed:
                return jsonify({
                    "error": "Pontos insuficientes",
                    "points_needed": points_needed,
                    "points_available": user.points,
                    "upgrade_required": True
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ========== HELPER FUNCTIONS ==========

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def deduct_points(user_id, points):
    user = db_session.query(User).filter_by(id=user_id).first()
    if user and not user.is_premium:
        user.points -= points
        usage = UsageHistory(user_id=user_id, action="AI_CALL", points_used=points)
        db_session.add(usage)
        db_session.commit()

def get_user_info(user_id):
    user = db_session.query(User).filter_by(id=user_id).first()
    if user:
        return {
            "email": user.email,
            "name": user.name,
            "is_premium": user.is_premium,
            "points": user.points
        }
    return None

# ========== GEMINI API (CORRIGIDA) ==========

def call_gemini_api(prompt, images=None):
    """Chamada para Gemini 2.0 Flash com suporte a múltiplas imagens"""
    
    print(f"📡 Chamando Gemini 2.0 Flash...")
    
    if not GEMINI_API_KEY:
        return "❌ GEMINI_API_KEY não configurada!"

    # Modelo correto que está funcionando
    model = "gemini-2.0-flash-exp"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    
    # Preparar partes do conteúdo
    parts = [{"text": prompt}]
    
    # Adicionar imagens se houver
    if images:
        if not isinstance(images, list):
            images = [images]
        
        for img in images:
            if img:
                # Extrair MIME type e dados base64
                if "," in img:
                    mime_type = img.split(";")[0].split(":")[1]
                    base64_data = img.split(",")[1]
                else:
                    mime_type = "image/jpeg"
                    base64_data = img
                
                parts.append({
                    "inlineData": {
                        "mimeType": mime_type,
                        "data": base64_data
                    }
                })
    
    payload = {
        "contents": [{
            "parts": parts
        }],
        "generationConfig": {
            "temperature": 0.7,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 2048,
        }
    }

    try:
        response = requests.post(url, headers={'Content-Type': 'application/json'}, json=payload, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            text_result = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "")
            print(f"✅ Gemini respondeu com sucesso!")
            return text_result
        
        if response.status_code == 429:
            return "⚠️ Limite de requisições atingido. Aguarde alguns segundos."
        
        error_msg = response.json().get('error', {}).get('message', 'Erro desconhecido')
        print(f"❌ Erro Gemini: {error_msg}")
        return f"❌ Erro na API: {error_msg}"
        
    except Exception as e:
        print(f"❌ Exceção ao chamar Gemini: {str(e)}")
        return f"❌ Erro: {str(e)}"

# ========== ROTAS DE AUTENTICAÇÃO ==========

@app.route('/')
def index():
    return render_template('index.html', 
                         stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
                         logged_in='user_id' in session)

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        name = data.get('name', email.split('@')[0])
        
        if not email or not password:
            return jsonify({"error": "Email e senha são obrigatórios"}), 400
        
        existing_user = db_session.query(User).filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "Email já cadastrado"}), 400
        
        new_user = User(
            email=email,
            password=hash_password(password),
            name=name,
            points=FREE_POINTS
        )
        db_session.add(new_user)
        db_session.commit()
        
        session['user_id'] = new_user.id
        session['email'] = email
        
        return jsonify({
            "success": True,
            "message": "Cadastro realizado com sucesso!",
            "user": {
                "id": new_user.id,
                "email": email,
                "name": name,
                "points": FREE_POINTS
            }
        })
    except Exception as e:
        db_session.rollback()
        print(f"❌ Erro no registro: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        print(f"🔐 Tentativa de login para: {email}")
        
        if not email or not password:
            return jsonify({"error": "Email e senha são obrigatórios"}), 400
        
        # Buscar usuário por email primeiro
        user = db_session.query(User).filter_by(email=email).first()
        
        if not user:
            print(f"❌ Usuário não encontrado: {email}")
            return jsonify({"error": "Email ou senha incorretos"}), 401
        
        # Verificar senha
        hashed_input = hash_password(password)
        print(f"🔑 Hash armazenado: {user.password[:20]}...")
        print(f"🔑 Hash fornecido: {hashed_input[:20]}...")
        
        if user.password != hashed_input:
            print(f"❌ Senha incorreta para: {email}")
            return jsonify({"error": "Email ou senha incorretos"}), 401
        
        session['user_id'] = user.id
        session['email'] = email
        session.permanent = True  # Tornar sessão permanente
        
        print(f"✅ Login bem-sucedido: {email}")
        
        return jsonify({
            "success": True,
            "message": "Login realizado com sucesso!",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "is_premium": user.is_premium,
                "points": user.points
            }
        })
    except Exception as e:
        print(f"❌ Erro no login: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logout realizado"})

@app.route('/api/user/info', methods=['GET'])
@login_required
def user_info():
    info = get_user_info(session['user_id'])
    if info:
        return jsonify(info)
    return jsonify({"error": "Usuário não encontrado"}), 404

# ========== ROTAS DE CHAT IA ==========

@app.route('/api/chat', methods=['POST'])
@login_required
@check_points(POINTS_PER_AI_CALL)
def chat():
    try:
        data = request.json
        prompt = data.get('prompt')
        images = data.get('images', [])  # Agora aceita múltiplas imagens
        
        if not prompt:
            return jsonify({"error": "Prompt é obrigatório"}), 400
        
        user_info_data = get_user_info(session['user_id'])
        
        if not user_info_data['is_premium']:
            deduct_points(session['user_id'], POINTS_PER_AI_CALL)
        
        result = call_gemini_api(prompt, images)
        updated_info = get_user_info(session['user_id'])
        
        return jsonify({
            "result": result,
            "points_remaining": updated_info['points'],
            "is_premium": updated_info['is_premium']
        })
    except Exception as e:
        print(f"❌ Erro no chat: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE PETS ==========

@app.route('/api/pets', methods=['GET'])
@login_required
def get_pets():
    pets = db_session.query(Pet).filter_by(user_id=session['user_id']).all()
    result = []
    for p in pets:
        # Contar refeições dos últimos 7 dias
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        meals = db_session.query(Meal).filter(
            Meal.pet_id == p.id,
            Meal.timestamp >= seven_days_ago
        ).all()
        
        result.append({
            "id": p.id,
            "name": p.name,
            "breed": p.breed,
            "type": p.type,
            "weight": p.weight,
            "photo_url": p.photo_url,
            "meal_count": len(meals)
        })
    return jsonify(result)

@app.route('/api/pets/<int:pet_id>', methods=['PUT'])
@login_required
def update_pet(pet_id):
    """Atualizar informações do pet"""
    try:
        data = request.json
        pet = db_session.query(Pet).filter_by(id=pet_id, user_id=session['user_id']).first()
        
        if not pet:
            return jsonify({"error": "Pet não encontrado"}), 404
        
        if 'weight' in data:
            pet.weight = data['weight']
        if 'breed' in data:
            pet.breed = data['breed']
        if 'name' in data:
            pet.name = data['name']
        if 'type' in data:
            pet.type = data['type']
            
        db_session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/pets/<int:pet_id>', methods=['DELETE'])
@login_required
def delete_pet(pet_id):
    """Deletar pet"""
    try:
        pet = db_session.query(Pet).filter_by(id=pet_id, user_id=session['user_id']).first()
        
        if not pet:
            return jsonify({"error": "Pet não encontrado"}), 404
        
        db_session.delete(pet)
        db_session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE REFEIÇÕES ==========

@app.route('/api/meals/<int:pet_id>', methods=['GET'])
@login_required
def get_meals(pet_id):
    """Retorna refeições dos últimos 7 dias"""
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    meals = db_session.query(Meal).filter(
        Meal.pet_id == pet_id,
        Meal.timestamp >= seven_days_ago
    ).all()
    
    # Agrupar por dia
    meals_by_day = {}
    for meal in meals:
        day = meal.timestamp.strftime('%Y-%m-%d')
        meals_by_day[day] = meals_by_day.get(day, 0) + 1
    
    # Criar array dos últimos 7 dias
    result = []
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        result.append(meals_by_day.get(day, 0))
    
    return jsonify(result)

@app.route('/api/meals/<int:pet_id>', methods=['POST'])
@login_required
def add_meal(pet_id):
    try:
        meal = Meal(pet_id=pet_id)
        db_session.add(meal)
        db_session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE VACINAS ==========

@app.route('/api/vaccines/<int:pet_id>', methods=['GET'])
@login_required
def get_vaccines(pet_id):
    vaccines = db_session.query(Vaccine).filter_by(pet_id=pet_id).all()
    return jsonify([{
        "id": v.id,
        "name": v.name,
        "scheduled_date": v.scheduled_date.isoformat() if v.scheduled_date else None,
        "applied_date": v.applied_date.isoformat() if v.applied_date else None,
        "is_applied": v.is_applied
    } for v in vaccines])

@app.route('/api/vaccines/<int:pet_id>', methods=['POST'])
@login_required
def add_vaccine(pet_id):
    try:
        data = request.json
        vaccine = Vaccine(
            pet_id=pet_id,
            name=data['name'],
            scheduled_date=datetime.fromisoformat(data['scheduled_date']) if data.get('scheduled_date') else None,
            is_applied=data.get('is_applied', False)
        )
        db_session.add(vaccine)
        db_session.commit()
        return jsonify({"success": True, "vaccine_id": vaccine.id})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/vaccines/<int:vaccine_id>/apply', methods=['POST'])
@login_required
def apply_vaccine(vaccine_id):
    try:
        vaccine = db_session.query(Vaccine).filter_by(id=vaccine_id).first()
        if vaccine:
            vaccine.is_applied = True
            vaccine.applied_date = datetime.utcnow()
            db_session.commit()
            return jsonify({"success": True})
        return jsonify({"error": "Vacina não encontrada"}), 404
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE PAGAMENTO STRIPE ==========

@app.route('/api/stripe/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user = db_session.query(User).filter_by(id=session['user_id']).first()
        
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={"user_id": user.id}
            )
            user.stripe_customer_id = customer.id
            db_session.commit()
        
        base_url = request.host_url.rstrip('/')
        
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            mode='subscription',
            line_items=[{
                'price_data': {
                    'currency': 'brl',
                    'product_data': {
                        'name': 'VetAI Nexus Premium',
                        'description': 'Acesso ilimitado a todas as funcionalidades de IA',
                    },
                    'unit_amount': 2990,
                    'recurring': {'interval': 'month'},
                },
                'quantity': 1,
            }],
            success_url=f'{base_url}/payment-success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{base_url}/payment-cancel',
        )
        
        return jsonify({"checkout_url": checkout_session.url})
    except Exception as e:
        print(f"❌ Erro ao criar checkout: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Webhook secret not configured"}), 500
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']
        customer_id = session_data['customer']
        subscription_id = session_data.get('subscription')
        
        user = db_session.query(User).filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.is_premium = True
            user.subscription_id = subscription_id
            user.subscription_end = datetime.now() + timedelta(days=30)
            db_session.commit()
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        user = db_session.query(User).filter_by(stripe_customer_id=customer_id).first()
        if user:
            user.is_premium = False
            db_session.commit()
    
    return jsonify({"success": True})

@app.route('/payment-success')
def payment_success():
    return render_template('payment_success.html')

@app.route('/payment-cancel')
def payment_cancel():
    return render_template('payment_cancel.html')

# ========== ROTA DE TESTE ==========

@app.route('/api/test-gemini', methods=['GET'])
def test_gemini():
    result = call_gemini_api("Diga apenas: OK, estou funcionando!")
    return jsonify({
        "test_result": result,
        "api_key_configured": bool(GEMINI_API_KEY),
        "api_key_preview": GEMINI_API_KEY[:10] + "..." if GEMINI_API_KEY else "NOT SET",
        "database": "PostgreSQL" if "postgresql" in DATABASE_URL else "SQLite"
    })

# ========== ROTAS DE DEBUG (REMOVER EM PRODUÇÃO) ==========

# ATENÇÃO: Estas rotas expõem dados sensíveis! 
# Comente ou remova antes de fazer deploy em produção!

# @app.route('/api/debug/users', methods=['GET'])
# def debug_users():
#     """Rota de debug para ver usuários cadastrados"""
#     users = db_session.query(User).all()
#     return jsonify([{
#         "id": u.id,
#         "email": u.email,
#         "name": u.name,
#         "password_hash": u.password[:20] + "...",
#         "is_premium": u.is_premium,
#         "points": u.points
#     } for u in users])

# @app.route('/api/debug/session', methods=['GET'])
# def debug_session():
#     """Rota de debug para verificar sessão"""
#     return jsonify({
#         "session_data": dict(session),
#         "user_id": session.get('user_id'),
#         "email": session.get('email')
#     })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)