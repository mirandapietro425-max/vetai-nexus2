import os
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import requests
import stripe

# Carrega variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret-key-change-me")
CORS(app)

# Configurações
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL")

# Validação crítica
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
    DATABASE_URL = "sqlite:///vetai.db"  # Fallback para desenvolvimento
else:
    # Render usa postgres://, SQLAlchemy precisa postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
db_session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

# Configuração de Pontos
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
    
    pets = relationship("Pet", back_populates="user")
    usage_history = relationship("UsageHistory", back_populates="user")

class Pet(Base):
    __tablename__ = 'pets'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(255), nullable=False)
    breed = Column(String(255))
    type = Column(String(100))
    weight = Column(Float)
    photo_url = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="pets")

class UsageHistory(Base):
    __tablename__ = 'usage_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(String(255), nullable=False)
    points_used = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="usage_history")

def init_db():
    """Inicializa o banco de dados"""
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
    """Decorator para verificar se o usuário tem pontos suficientes"""
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
    """Hash de senha simples"""
    return hashlib.sha256(password.encode()).hexdigest()

def deduct_points(user_id, points):
    """Deduz pontos do usuário"""
    user = db_session.query(User).filter_by(id=user_id).first()
    if user and not user.is_premium:
        user.points -= points
        usage = UsageHistory(user_id=user_id, action="AI_CALL", points_used=points)
        db_session.add(usage)
        db_session.commit()

def get_user_info(user_id):
    """Retorna informações do usuário"""
    user = db_session.query(User).filter_by(id=user_id).first()
    if user:
        return {
            "email": user.email,
            "name": user.name,
            "is_premium": user.is_premium,
            "points": user.points
        }
    return None

# ========== GEMINI API ==========

def call_gemini_api(prompt, base64_image=None):
    """Função auxiliar para comunicação com a API do Gemini"""
    
    print(f"📡 Iniciando chamada Gemini API...")
    
    if not GEMINI_API_KEY:
        return "❌ GEMINI_API_KEY não configurada no servidor!"

    models = [
        "gemini-2.0-flash-exp",
        "gemini-1.5-flash-latest",
        "gemini-1.5-flash"
    ]
    
    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }

        if base64_image:
            if "," in base64_image:
                mime_type = base64_image.split(";")[0].split(":")[1]
                base64_data = base64_image.split(",")[1]
            else:
                mime_type = "image/jpeg"
                base64_data = base64_image
                
            payload["contents"][0]["parts"].append({
                "inlineData": {
                    "mimeType": mime_type,
                    "data": base64_data
                }
            })

        try:
            response = requests.post(url, headers={'Content-Type': 'application/json'}, json=payload, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                text_result = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "")
                print(f"✅ Sucesso com modelo {model}!")
                return text_result
            
            if response.status_code == 404:
                continue
            
            if response.status_code == 429:
                return "⚠️ Limite de requisições atingido. Aguarde alguns segundos."
            
        except Exception as e:
            print(f"❌ Erro ao chamar {model}: {str(e)}")
            continue
    
    return "❌ Nenhum modelo Gemini respondeu. Verifique a chave API."

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
        
        if not email or not password:
            return jsonify({"error": "Email e senha são obrigatórios"}), 400
        
        user = db_session.query(User).filter_by(email=email, password=hash_password(password)).first()
        
        if not user:
            return jsonify({"error": "Email ou senha incorretos"}), 401
        
        session['user_id'] = user.id
        session['email'] = email
        
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
        image = data.get('image')
        
        if not prompt:
            return jsonify({"error": "Prompt é obrigatório"}), 400
        
        user_info_data = get_user_info(session['user_id'])
        
        if not user_info_data['is_premium']:
            deduct_points(session['user_id'], POINTS_PER_AI_CALL)
        
        result = call_gemini_api(prompt, image)
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
    return jsonify([{
        "id": p.id,
        "name": p.name,
        "breed": p.breed,
        "type": p.type,
        "weight": p.weight,
        "photo_url": p.photo_url
    } for p in pets])

@app.route('/api/pets', methods=['POST'])
@login_required
def create_pet():
    try:
        data = request.json
        new_pet = Pet(
            user_id=session['user_id'],
            name=data['name'],
            breed=data.get('breed'),
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
    """Rota de teste para debug da API Gemini"""
    result = call_gemini_api("Diga apenas: OK, estou funcionando!")
    return jsonify({
        "test_result": result,
        "api_key_configured": bool(GEMINI_API_KEY),
        "api_key_preview": GEMINI_API_KEY[:10] + "..." if GEMINI_API_KEY else "NOT SET",
        "database": "PostgreSQL" if "postgresql" in DATABASE_URL else "SQLite"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)