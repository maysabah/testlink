function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const icon = button.querySelector('i');
    if (input.type === "password") {
      input.type = "text";
      icon.classList.remove('bi-eye');
      icon.classList.add('bi-eye-slash');
    } else {
      input.type = "password";
      icon.classList.remove('bi-eye-slash');
      icon.classList.add('bi-eye');
    }
  }


  console.log("JavaScript is loaded"); // للتحقق من تحميل الكود

// تحديد العناصر
const themeToggler = document.getElementById('theme-toggler');
const themeIcon = document.getElementById('theme-icon');

if (themeToggler && themeIcon) {
    console.log("Elements are found");

    // دالة تغيير الثيم بناءً على الوقت
    function setThemeBasedOnTime(mockHour = null) {
        const hour = mockHour !== null ? mockHour : new Date().getHours();
        console.log("Current Hour:", hour);

        if (hour >= 18 || hour < 6) {
            document.body.classList.add('dark-theme');
            themeIcon.classList.replace('bi-moon', 'bi-sun');
            themeIcon.style.color = 'yellow';
            console.log("Dark theme applied");
        } else {
            document.body.classList.remove('dark-theme');
            themeIcon.classList.replace('bi-sun', 'bi-moon');
            themeIcon.style.color = 'white';
            console.log("Light theme applied");
        }
    }

    // تنفيذ عند التحميل
    document.addEventListener('DOMContentLoaded', () => {
        setThemeBasedOnTime(); // تغيير وقت المحاكاة هنا
    });

    themeToggler.addEventListener('click', () => {
        document.body.classList.toggle('dark-theme');
        if (document.body.classList.contains('dark-theme')) {
            themeIcon.classList.replace('bi-moon', 'bi-sun');
            themeIcon.style.color = 'yellow';
            console.log("Dark theme toggled manually");
        } else {
            themeIcon.classList.replace('bi-sun', 'bi-moon');
            themeIcon.style.color = 'white';
            console.log("Light theme toggled manually");
        }
    });
} else {
    console.error("Required elements not found");
}

function generatePassword() {
    const length = 12; // طول كلمة المرور
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
      password += charset.charAt(Math.floor(Math.random() * n));
    }
    const passwordField = document.getElementById("password");
    passwordField.value = password;
    passwordField.focus();
    checkPasswordStrength(); // تحديث مؤشر القوة
  }

  function checkPasswordStrength() {
    const password = document.getElementById("password").value;
    const strengthBar = document.getElementById("passwordStrengthBar");
    const strengthText = document.getElementById("passwordStrengthText");

    let strength = 0;

    // تحقق من المعايير
    if (password.length >= 8) strength += 25; // الطول
    if (/[A-Z]/.test(password)) strength += 25; // أحرف كبيرة
    if (/[0-9]/.test(password)) strength += 25; // أرقام
    if (/[@$!%*?&]/.test(password)) strength += 25; // رموز خاصة

    // تحديث الشريط
    strengthBar.style.width = strength + "%";
    if (strength <= 25) {
      strengthBar.className = "progress-bar bg-danger"; // ضعيف
      strengthText.textContent = "Weak";
      strengthText.className = "text-danger";
    } else if (strength <= 50) {
      strengthBar.className = "progress-bar bg-warning"; // متوسط
      strengthText.textContent = "Fair";
      strengthText.className = "text-warning";
    } else if (strength <= 75) {
      strengthBar.className = "progress-bar bg-info"; // جيد
      strengthText.textContent = "Good";
      strengthText.className = "text-info";
    } else {
      strengthBar.className = "progress-bar bg-success"; // قوي
      strengthText.textContent = "Strong";
      strengthText.className = "text-success";
    }
  }