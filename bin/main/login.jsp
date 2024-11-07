<form action="login" method="post" onsubmit="return validateForm()">
    <input type="text" name="username" placeholder="Username" required />
    <input type="password" name="password" placeholder="Password" required />
    <input type="submit" value="Login" />
</form>

<script>
    function validateForm() {
        const username = document.forms[0]["username"].value;
        const password = document.forms[0]["password"].value;
        if (username.trim() === "" || password.trim() === "") {
            alert("Please fill out all fields.");
            return false;
        }
        return true;
    }
</script>
