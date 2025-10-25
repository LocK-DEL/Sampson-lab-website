const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');
const registerForm = document.getElementById('register-form');
const registerMessage = document.getElementById('register-message');

registerBtn.addEventListener('click', () => {
  container.classList.add('active');
});

loginBtn.addEventListener('click', () => {
  container.classList.remove('active');
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const formData = new FormData(registerForm);
  const username = formData.get('username');
  const password = formData.get('password');

  registerMessage.textContent = '正在注册，请稍候…';
  registerMessage.className = 'message info';

  try {
    const response = await fetch('/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    const result = await response.json().catch(() => ({}));

    if (response.ok && result.success) {
      registerMessage.textContent = result.message || '注册成功';
      registerMessage.className = 'message success';
      registerForm.reset();
    } else {
      registerMessage.textContent = result.message || '注册失败，请稍后重试';
      registerMessage.className = 'message error';
    }
  } catch (error) {
    registerMessage.textContent = '网络异常，请稍后重试';
    registerMessage.className = 'message error';
  }
});
