import os
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import json
import time
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import stripe

# Carrega variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
CORS(app)

# Configurações - SEM valores padrão com chaves reais!
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

if not STRIPE_SECRET_KEY:
    print("⚠️  AVISO: STRIPE_SECRET_KEY não configurada!")
if not STRIPE_WEBHOOK_SECRET:
    print("⚠️  AVISO: STRIPE_WEBHOOK_SECRET não configurada!")

stripe.api_key = STRIPE_SECRET_KEY

# Configuração de Pontos
FREE_POINTS = 50
POINTS_PER_AI_CALL = 5
PREMIUM_UNLIMITED = True

# ========== DATABASE ==========

def init_db():
    """Inicializa o banco de dados"""
    conn = sqlite3.connect('vetai.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        is_premium INTEGER DEFAULT 0,
        points INTEGER DEFAULT 50,
        stripe_customer_id TEXT,
        subscription_id TEXT,
        subscription_end DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS pets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        breed TEXT,
        type TEXT,
        weight REAL,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS usage_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        points_used INTEGER DEFAULT 0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

init_db()

# ... (resto do código continua igual)

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
            
            conn = sqlite3.connect('vetai.db')
            c = conn.cursor()
            c.execute("SELECT points, is_premium FROM users WHERE id = ?", (user_id,))
            result = c.fetchone()
            conn.close()
            
            if not result:
                return jsonify({"error": "Usuário não encontrado"}), 404
            
            points, is_premium = result
            
            if is_premium:
                return f(*args, **kwargs)
            
            if points < points_needed:
                return jsonify({
                    "error": "Pontos insuficientes",
                    "points_needed": points_needed,
                    "points_available": points,
                    "upgrade_required": True
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ========== HELPER FUNCTIONS ==========

def hash_password(password):
    """Hash de senha simples (use bcrypt em produção)"""
    return hashlib.sha256(password.encode()).hexdigest()

def deduct_points(user_id, points):
    """Deduz pontos do usuário"""
    conn = sqlite3.connect('vetai.db')
    c = conn.cursor()
    c.execute("UPDATE users SET points = points - ? WHERE id = ?", (points, user_id))
    c.execute("INSERT INTO usage_history (user_id, action, points_used) VALUES (?, ?, ?)",
              (user_id, "AI_CALL", points))
    conn.commit()
    conn.close()

def get_user_info(user_id):
    """Retorna informações do usuário"""
    conn = sqlite3.connect('vetai.db')
    c = conn.cursor()
    c.execute("SELECT email, name, is_premium, points FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    if result:
        return {
            "email": result[0],
            "name": result[1],
            "is_premium": bool(result[2]),
            "points": result[3]
        }
    return None

# ========== GEMINI API ==========

def call_gemini_api(prompt, base64_image=None):
    """Função auxiliar para comunicação com a API do Gemini 2.0"""
    if not GEMINI_API_KEY:
        return "Erro: GEMINI_API_KEY não configurada."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={GEMINI_API_KEY}"
    
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

    for i in range(3):
        try:
            response = requests.post(
                url,
                headers={'Content-Type': 'application/json'},
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "")
            
            error_data = response.json() if response.text else {}
            print(f"Erro API Gemini ({response.status_code}): {json.dumps(error_data, indent=2)}")
            
            if response.status_code == 404:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={GEMINI_API_KEY}"
            
            time.sleep(1 * (i + 1))
        except Exception as e:
            print(f"Erro na tentativa {i+1}: {str(e)}")
            time.sleep(1)
            
    return "Erro: O motor de IA Nexus (Gemini 2.0) não respondeu. Verifique sua cota no Google AI Studio."

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
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return jsonify({"error": "Email já cadastrado"}), 400
        
        c.execute(
            "INSERT INTO users (email, password, name, points) VALUES (?, ?, ?, ?)",
            (email, hash_password(password), name, FREE_POINTS)
        )
        user_id = c.lastrowid
        conn.commit()
        conn.close()
        
        session['user_id'] = user_id
        session['email'] = email
        
        return jsonify({
            "success": True,
            "message": "Cadastro realizado com sucesso!",
            "user": {"id": user_id, "email": email, "name": name, "points": FREE_POINTS}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email e senha são obrigatórios"}), 400
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute("SELECT id, name, is_premium, points FROM users WHERE email = ? AND password = ?",
                 (email, hash_password(password)))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "Email ou senha incorretos"}), 401
        
        user_id, name, is_premium, points = result
        
        session['user_id'] = user_id
        session['email'] = email
        
        return jsonify({
            "success": True,
            "message": "Login realizado com sucesso!",
            "user": {
                "id": user_id,
                "email": email,
                "name": name,
                "is_premium": bool(is_premium),
                "points": points
            }
        })
    except Exception as e:
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
        
        user_info = get_user_info(session['user_id'])
        if not user_info['is_premium']:
            deduct_points(session['user_id'], POINTS_PER_AI_CALL)
        
        result = call_gemini_api(prompt, image)
        
        updated_info = get_user_info(session['user_id'])
        
        return jsonify({
            "result": result,
            "points_remaining": updated_info['points'],
            "is_premium": updated_info['is_premium']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE PETS ==========

@app.route('/api/pets', methods=['GET'])
@login_required
def get_pets():
    conn = sqlite3.connect('vetai.db')
    c = conn.cursor()
    c.execute("SELECT id, name, breed, type, weight, photo_url FROM pets WHERE user_id = ?",
             (session['user_id'],))
    pets = []
    for row in c.fetchall():
        pets.append({
            "id": row[0],
            "name": row[1],
            "breed": row[2],
            "type": row[3],
            "weight": row[4],
            "photo_url": row[5]
        })
    conn.close()
    return jsonify(pets)

@app.route('/api/pets', methods=['POST'])
@login_required
def create_pet():
    try:
        data = request.json
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute(
            "INSERT INTO pets (user_id, name, breed, type, weight, photo_url) VALUES (?, ?, ?, ?, ?, ?)",
            (session['user_id'], data['name'], data.get('breed'), data.get('type', 'Cachorro'),
             data.get('weight', 0), data.get('photo_url'))
        )
        pet_id = c.lastrowid
        conn.commit()
        conn.close()
        return jsonify({"success": True, "pet_id": pet_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ========== ROTAS DE PAGAMENTO STRIPE ==========

@app.route('/api/stripe/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user_info = get_user_info(session['user_id'])
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute("SELECT stripe_customer_id FROM users WHERE id = ?", (session['user_id'],))
        result = c.fetchone()
        stripe_customer_id = result[0] if result else None
        
        if not stripe_customer_id:
            customer = stripe.Customer.create(
                email=user_info['email'],
                metadata={"user_id": session['user_id']}
            )
            stripe_customer_id = customer.id
            c.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?",
                     (stripe_customer_id, session['user_id']))
            conn.commit()
        
        conn.close()
        
        # URL base (funciona tanto localmente quanto em produção)
        base_url = request.host_url.rstrip('/')
        
        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=['card'],
            mode='subscription',
            line_items=[{
                'price_data': {
                    'currency': 'brl',
                    'product_data': {
                        'name': 'VetAI Nexus Premium',
                        'description': 'Acesso ilimitado a todas as funcionalidades de IA',
                    },
                    'unit_amount': 2990,  # R$ 29,90
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            success_url=f'{base_url}/payment-success?session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=f'{base_url}/payment-cancel',
        )
        
        print(f"✅ Checkout session created: {checkout_session.id}")
        return jsonify({"checkout_url": checkout_session.url})
    except Exception as e:
        print(f"❌ Erro ao criar checkout: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    print(f"📨 Webhook recebido - Signature: {sig_header[:20]}...")
    
    if not STRIPE_WEBHOOK_SECRET:
        print("⚠️  STRIPE_WEBHOOK_SECRET não configurado!")
        return jsonify({"error": "Webhook secret not configured"}), 500
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        print(f"✅ Webhook verificado - Tipo: {event['type']}")
    except ValueError as e:
        print(f"❌ Payload inválido: {e}")
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        print(f"❌ Assinatura inválida: {e}")
        return jsonify({"error": "Invalid signature"}), 400
    
    # Processa eventos do Stripe
    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']
        customer_id = session_data['customer']
        subscription_id = session_data.get('subscription')
        
        print(f"💳 Pagamento confirmado - Customer: {customer_id}")
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute(
            "UPDATE users SET is_premium = 1, subscription_id = ?, subscription_end = ? WHERE stripe_customer_id = ?",
            (subscription_id, (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'), customer_id)
        )
        conn.commit()
        conn.close()
        
        print(f"✅ Usuário atualizado para Premium")
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        print(f"❌ Assinatura cancelada - Customer: {customer_id}")
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute(
            "UPDATE users SET is_premium = 0 WHERE stripe_customer_id = ?",
            (customer_id,)
        )
        conn.commit()
        conn.close()
        
        print(f"✅ Premium removido do usuário")
    
    return jsonify({"success": True})

@app.route('/payment-success')
def payment_success():
    return render_template('payment_success.html')

@app.route('/payment-cancel')
def payment_cancel():
    return render_template('payment_cancel.html')

# ========== ROTAS DE PONTOS ==========

@app.route('/api/points/add', methods=['POST'])
@login_required
def add_points():
    """Rota para adicionar pontos (pode ser usada para recompensas futuras)"""
    try:
        data = request.json
        points = data.get('points', 10)
        
        conn = sqlite3.connect('vetai.db')
        c = conn.cursor()
        c.execute("UPDATE users SET points = points + ? WHERE id = ?", (points, session['user_id']))
        conn.commit()
        conn.close()
        
        updated_info = get_user_info(session['user_id'])
        return jsonify({"success": True, "points": updated_info['points']})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=os.environ.get('DEBUG', 'False') == 'True', host='0.0.0.0', port=port)