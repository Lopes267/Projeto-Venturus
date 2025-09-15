import json
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'pessoas.json')
CORS(app)

def carregar_pessoas():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def salvar_pessoas(pessoas):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(pessoas, f, ensure_ascii=False, indent=2)

@app.route('/login', methods=['POST'])
def login():
    dados = request.json or {}
    email = (dados.get('email') or '').strip().lower()
    senha = dados.get('senha') or ''
    pessoas = carregar_pessoas()

    print(f"[DEBUG] Tentativa login: email='{email}', total_pessoas={len(pessoas)}")
    pessoa = next((p for p in pessoas if (p.get('email') or '').lower() == email), None)
    if not pessoa:
        print("[DEBUG] Usuário não encontrado")
        return jsonify({'success': False, 'message': 'Usuário ou senha incorretos'}), 401

    senha_hash = pessoa.get('senha_hash', '')
    print(f"[DEBUG] Usuário encontrado: nome='{pessoa.get('nome')}', tem_hash={'sim' if senha_hash else 'não'}")

    ok = False
    try:
        ok = check_password_hash(senha_hash, senha)
    except Exception as e:
        print("[DEBUG] Erro check_password_hash:", e)

    # fallback se registro antigo tiver senha em texto plano
    if not ok and 'senha' in pessoa:
        if pessoa.get('senha') == senha:
            ok = True
            print("[DEBUG] Fallback: senha em texto plano bateu")

    if not ok:
        print("[DEBUG] Senha inválida")
        return jsonify({'success': False, 'message': 'Usuário ou senha incorretos'}), 401

    print("[DEBUG] Login OK para:", pessoa.get('email'))
    return jsonify({
        'success': True,
        'tipo': pessoa['tipo'],
        'especialidade': pessoa.get('especialidade', ''),
        'nome': pessoa.get('nome', '')
    })

@app.route('/registrar', methods=['POST'])
def registrar_pessoa():
    pessoas = carregar_pessoas()
    dados = request.json
    nome = (dados.get('nome') or '').strip()
    email = (dados.get('email') or '').strip().lower()
    tipo = dados.get('tipo')
    especialidade = dados.get('especialidade') if tipo == 'medico' else None
    senha = dados.get('senha')

    if tipo not in ['medico', 'cliente']:
        return jsonify({'erro': 'Tipo inválido'}), 400
    if not senha or not email or not nome:
        return jsonify({'erro': 'Nome, email e senha são obrigatórios'}), 400
    if any(p.get('email', '').lower() == email for p in pessoas):
        return jsonify({'erro': 'E-mail já cadastrado'}), 400

    # força algoritmo padrão
    senha_hash = generate_password_hash(senha, method='pbkdf2:sha256')
    pessoa = {
        'nome': nome,
        'email': email,
        'tipo': tipo,
        'especialidade': especialidade,
        'senha_hash': senha_hash
    }
    pessoas.append(pessoa)
    salvar_pessoas(pessoas)
    return jsonify({'mensagem': 'Pessoa registrada com sucesso!', 'pessoa': pessoa}), 201

@app.route('/pessoas', methods=['GET'])
def listar_pessoas():
    pessoas = carregar_pessoas()
    return jsonify(pessoas)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
    
