// Function to validate password strength dynamically
function validatePassword() {
    var password = document.getElementById("password").value;
    
    // Validate length
    var length = document.getElementById("length");
    if (password.length >= 8) {
        length.classList.remove("invalid");
        length.classList.add("valid");
    } else {
        length.classList.remove("valid");
        length.classList.add("invalid");
    }
    
    // Validate number
    var number = document.getElementById("number");
    if (/\d/.test(password)) {
        number.classList.remove("invalid");
        number.classList.add("valid");
    } else {
        number.classList.remove("valid");
        number.classList.add("invalid");
    }
    
    // Validate special character
    var special = document.getElementById("special");
    if (/[^A-Za-z0-9]/.test(password)) {
        special.classList.remove("invalid");
        special.classList.add("valid");
    } else {
        special.classList.remove("valid");
        special.classList.add("invalid");
    }
}

// Attach event listener for input on password field
var passwordInput = document.getElementById("password");
passwordInput.addEventListener("input", function() {
    // Show password requirements only when typing
    var passwordRequirements = document.getElementById("password-requirements");
    if (passwordInput.value.length > 0) {
        passwordRequirements.style.display = "block";
    } else {
        passwordRequirements.style.display = "none";
    }
    
    // Validate password strength
    validatePassword();
});

// Function to compare password and confirm password
function validateForm() {
    var password = document.getElementById("password").value;
    var confirm_password = document.getElementById("confirm_password").value;
    var passwordMatch = document.getElementById("password-match");

    // Check if passwords match
    if (password !== confirm_password) {
        passwordMatch.style.display = "block";
        return false; // Prevent form submission
    } else {
        passwordMatch.style.display = "none";
        // Validate password strength
        validatePassword();
        
        // Check if all password requirements are met
        var lengthValid = document.getElementById("length").classList.contains("valid");
        var numberValid = document.getElementById("number").classList.contains("valid");
        var specialValid = document.getElementById("special").classList.contains("valid");
        
        if (!lengthValid || !numberValid || !specialValid) {
            alert("Please ensure your password meets all requirements.");
            return false; // Prevent form submission
        }
        
        return true; // Allow form submission
    }
}
