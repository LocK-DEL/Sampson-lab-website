document.getElementById('submit-btn').addEventListener('click', function() {
    let score = 0;

    if (document.querySelector('input[name="q1"]:checked')?.value === 'C') {
        score++;
    }
    if (document.querySelector('input[name="q2"]:checked')?.value === 'A') {
        score++;
    }

    const total = 2;
    document.getElementById('result').innerText = `您本次得分：${score} / ${total}`;
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
  if (window.innerWidth <= 768) {
    window.location.href = "mobile.html";
  }
});
