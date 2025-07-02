// 可扩展功能，如导航动画、滚动特效等
console.log("科研实验组网页已加载");
document.addEventListener("DOMContentLoaded", function () {
  const toggleBtn = document.querySelector(".toggle-btn");
  const sidenav = document.querySelector(".sidenav");
  const mainContent = document.querySelector(".main-content");

  toggleBtn?.addEventListener("click", () => {
    sidenav.classList.toggle("collapsed");
    mainContent.classList.toggle("collapsed");
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const images = document.querySelectorAll("img.lazy-blur-img");
  const observer = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if(entry.isIntersecting){
        const img = entry.target;
        img.src = img.dataset.src;
        img.onload = () => img.classList.add("loaded");
        observer.unobserve(img);
      }
    });
  }, {
    threshold: 0.1
  });

  images.forEach(img => observer.observe(img));
});
document.addEventListener('DOMContentLoaded', function () {
  // 下拉菜单点击展开适配手机
  const dropdowns = document.querySelectorAll('nav ul li.dropdown');

  dropdowns.forEach(dropdown => {
    const link = dropdown.querySelector('a');
    const submenu = dropdown.querySelector('ul.dropdown-content');

    link.addEventListener('click', function (e) {
      // 防止链接跳转
      e.preventDefault();

      // 关闭其他菜单
      dropdowns.forEach(d => {
        if (d !== dropdown) {
          d.querySelector('ul.dropdown-content').style.display = 'none';
        }
      });

      // 切换当前菜单显示隐藏
      if (submenu.style.display === 'block') {
        submenu.style.display = 'none';
      } else {
        submenu.style.display = 'block';
      }
    });
  });

  // 点击其他地方自动关闭下拉菜单
  document.addEventListener('click', function (e) {
    if (!e.target.closest('nav')) {
      dropdowns.forEach(d => {
        d.querySelector('ul.dropdown-content').style.display = 'none';
      });
    }
  });
});
document.addEventListener("DOMContentLoaded", function() {
    const btn = document.getElementById("backToTop");
    if (!btn) return;
    window.addEventListener("scroll", function() {
        if (window.scrollY > 300) {
            btn.style.display = "block";
        } else {
            btn.style.display = "none";
        }
    });
    btn.addEventListener("click", function(e) {
        e.stopPropagation(); // 防止冒泡影响导航
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
});
document.addEventListener('DOMContentLoaded', function() {
  // if (window.innerWidth <= 768) {
  //   window.location.href = "mobile.html";
  // }
});

