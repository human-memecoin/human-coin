// Theme Toggle
function toggleTheme() {
    const root = document.documentElement;
    const currentTheme = root.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    root.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const icon = document.querySelector('.theme-toggle i');
    icon.className = newTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
}

// Initialize theme from localStorage
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const icon = document.querySelector('.theme-toggle i');
    icon.className = savedTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
}

// Newsletter Form Handling
function handleNewsletterSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const emailInput = form.querySelector('input[type="email"]');
    const submitButton = form.querySelector('button');
    
    if (!emailInput.value) {
        showMessage('Please enter an email address', 'error');
        return;
    }

    // Add loading state
    form.classList.add('loading');
    submitButton.disabled = true;

    // Simulate form submission (replace with actual API call)
    setTimeout(() => {
        showMessage('Thank you for subscribing!', 'success');
        form.classList.remove('loading');
        submitButton.disabled = false;
        emailInput.value = '';
    }, 1500);
}

// Message Display
function showMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    const form = document.querySelector('.subscribe-form');
    form.parentNode.insertBefore(messageDiv, form.nextSibling);
    
    setTimeout(() => messageDiv.remove(), 3000);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    // Add form submission handler
    const newsletterForm = document.querySelector('.subscribe-form');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', handleNewsletterSubmit);
    }
});

// Add smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});
