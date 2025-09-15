// assets/js/script.js

document.addEventListener('DOMContentLoaded', () => {

    // --- LÓGICA DO FORMULÁRIO DE CONTATO (contato.html) ---
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const formStatus = document.getElementById('formStatus');
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const message = document.getElementById('message').value;

            if (name === '' || email === '' || message === '') {
                formStatus.textContent = 'Por favor, preencha todos os campos.';
                formStatus.style.color = 'var(--vermelho-erro)';
            } else {
                formStatus.textContent = 'Mensagem enviada com sucesso! Em breve entraremos em contato.';
                formStatus.style.color = 'var(--verde-sucesso)';
                contactForm.reset();
            }
        });
    }

    // --- LÓGICA DO FORMULÁRIO DE CADASTRO (cadastro.html) ---
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const registerStatus = document.getElementById('registerStatus');
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            if (name === '' || email === '' || password === '') {
                registerStatus.textContent = 'Por favor, preencha todos os campos.';
                registerStatus.style.color = 'var(--vermelho-erro)';
            } else {
                registerStatus.textContent = 'Cadastro realizado com sucesso!';
                registerStatus.style.color = 'var(--verde-sucesso)';
                // Aqui o back-end receberia os dados do novo usuário
            }
        });
    }

    // --- LÓGICA DO FORMULÁRIO DE LOGIN (login.html) ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const loginStatus = document.getElementById('loginStatus');
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            // Aqui você faria a validação com o back-end para saber se o login é válido
            // Para o projeto, vamos simular um login bem-sucedido
            if (email === 'medico@exemplo.com' && password === 'senha123') {
                loginStatus.textContent = 'Login de médico bem-sucedido. Redirecionando...';
                loginStatus.style.color = 'var(--verde-sucesso)';
                window.location.href = 'index.html'; // Redireciona para o dashboard do médico
            } else if (email === 'paciente@exemplo.com' && password === 'senha123') {
                loginStatus.textContent = 'Login de paciente bem-sucedido. Redirecionando...';
                loginStatus.style.color = 'var(--verde-sucesso)';
                window.location.href = 'dashboard-paciente.html'; // Redireciona para o dashboard do paciente
            } else {
                loginStatus.textContent = 'E-mail ou senha incorretos.';
                loginStatus.style.color = 'var(--vermelho-erro)';
            }
        });
    }
    
    // --- LÓGICA DO FORMULÁRIO DE PRÉ-EXAME (agendar-consulta.html) ---
    const preExamForm = document.getElementById('preExamForm');
    if (preExamForm) {
        preExamForm.addEventListener('submit', (event) => {
            event.preventDefault();
            const result = document.getElementById('result');
            const problemArea = document.getElementById('problemArea').value;

            let specialty = '';

            switch (problemArea) {
                case 'corpo':
                    specialty = 'Clínico Geral';
                    break;
                case 'cabeça':
                    specialty = 'Neurologista';
                    break;
                case 'abdômen':
                    specialty = 'Gastroenterologista';
                    break;
                case 'pele':
                    specialty = 'Dermatologista';
                    break;
                default:
                    specialty = 'Médico Clínico Geral';
                    break;
            }

            result.innerHTML = `<div class="alert alert-success" role="alert">Com base nos seus sintomas, o especialista mais indicado é: <strong>${specialty}</strong>.</div>`;
        });
    }
});
