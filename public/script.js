const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');
const registerForm = document.getElementById('register-form');
const registerMessage = document.getElementById('register-message');
const loginForm = document.getElementById('login-form');
const loginMessage = document.getElementById('login-message');

let csrfToken = null;

const setMessage = (element, text, type = '') => {
  if (!element) return;

  const classes = ['message'];
  if (type) {
    classes.push(type);
  }

  element.className = classes.join(' ');
  element.textContent = text;
};

const fetchCsrfToken = async () => {
  try {
    const response = await fetch('/csrf-token', {
      method: 'GET',
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error('获取 CSRF token 失败');
    }

    const data = await response.json();
    csrfToken = data && data.csrfToken ? data.csrfToken : null;
  } catch (error) {
    csrfToken = null;
    console.error(error);
  }
};

const ensureCsrfToken = async () => {
  if (!csrfToken) {
    await fetchCsrfToken();
  }

  return csrfToken;
};

fetchCsrfToken();

if (registerBtn && container) {
  registerBtn.addEventListener('click', () => {
    container.classList.add('active');
  });
}

if (loginBtn && container) {
  loginBtn.addEventListener('click', () => {
    container.classList.remove('active');
  });
}

if (registerForm && registerMessage) {
  registerForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const formData = new FormData(registerForm);
    const username = formData.get('username');
    const password = formData.get('password');

    setMessage(registerMessage, '正在注册，请稍候…', 'info');

    try {
      const token = await ensureCsrfToken();
      if (!token) {
        throw new Error('CSRF token 不可用');
      }

      const response = await fetch('/register', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({ username, password }),
      });

      const result = await response.json().catch(() => ({}));

      if (response.ok && result.success) {
        setMessage(registerMessage, result.message || '注册成功', 'success');
        registerForm.reset();
      } else {
        setMessage(
          registerMessage,
          result.message || '注册失败，请稍后重试',
          'error'
        );
      }
    } catch (error) {
      console.error(error);
      setMessage(registerMessage, '网络异常，请稍后重试', 'error');
    } finally {
      await fetchCsrfToken();
    }
  });
}

if (loginForm && loginMessage) {
  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const formData = new FormData(loginForm);
    const username = formData.get('username');
    const password = formData.get('password');

    setMessage(loginMessage, '正在登录，请稍候…', 'info');

    let skipTokenRefresh = false;

    try {
      const token = await ensureCsrfToken();
      if (!token) {
        throw new Error('CSRF token 不可用');
      }

      const response = await fetch('/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
        },
        body: JSON.stringify({ username, password }),
      });

      const result = await response.json().catch(() => ({}));

      if (response.ok && result.success) {
        skipTokenRefresh = true;
        csrfToken = result.csrfToken || csrfToken;
        setMessage(loginMessage, result.message || '登录成功', 'success');

        const redirectTarget = result.redirect || '/';
        setTimeout(() => {
          window.location.href = redirectTarget;
        }, 800);
      } else {
        setMessage(
          loginMessage,
          result.message || '登录失败，请稍后重试',
          'error'
        );
      }
    } catch (error) {
      console.error(error);
      setMessage(loginMessage, '网络异常，请稍后重试', 'error');
    } finally {
      if (!skipTokenRefresh) {
        await fetchCsrfToken();
      }
    }
  });
}
