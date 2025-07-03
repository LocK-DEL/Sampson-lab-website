console.log("科研实验组网页功能初始化");

document.addEventListener("DOMContentLoaded", function () {
  
  /*** 侧边栏切换 ***/
  const toggleBtn = document.querySelector(".toggle-btn");
  const sidenav = document.querySelector(".sidenav");
  const mainContent = document.querySelector(".main-content");

  if (toggleBtn && sidenav && mainContent) {
    toggleBtn.addEventListener("click", () => {
      sidenav.classList.toggle("collapsed");
      mainContent.classList.toggle("collapsed");
        });
      }
    });

  /*** 图片懒加载 ***/
  const images = document.querySelectorAll("img.lazy-blur-img");
  const imgObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        const src = img.dataset.src;
        if (src) {
          img.src = src;
          img.onload = () => img.classList.add("loaded");
        }
        observer.unobserve(img);
      }
    });
  }, {
    threshold: 0.1
  });

  images.forEach(img => imgObserver.observe(img));

  /*** 下拉菜单优化，兼容移动端点击和桌面悬停 ***/
  const dropdowns = document.querySelectorAll('nav ul li.dropdown');

  dropdowns.forEach(dropdown => {
    const link = dropdown.querySelector('a');
    const submenu = dropdown.querySelector('ul.dropdown-content');

    if (!link || !submenu) return;

    link.addEventListener('click', function (e) {
      e.preventDefault();
      const isVisible = submenu.style.display === 'block';

      dropdowns.forEach(d => {
        const sub = d.querySelector('ul.dropdown-content');
        if (sub) sub.style.display = 'none';
      });

      submenu.style.display = isVisible ? 'none' : 'block';
    });
  });

  document.addEventListener('click', function (e) {
    if (!e.target.closest('nav')) {
      dropdowns.forEach(d => {
        const sub = d.querySelector('ul.dropdown-content');
        if (sub) sub.style.display = 'none';
      });
    }
  });

  /*** 返回顶部按钮 ***/
  const backBtn = document.getElementById("backToTop");
  if (backBtn) {
    window.addEventListener("scroll", () => {
      backBtn.style.display = window.scrollY > 300 ? "block" : "none";
    });

    backBtn.addEventListener("click", (e) => {
      e.stopPropagation();
            window.scrollTo({ top: 0, behavior: "smooth" });
          });
        }

