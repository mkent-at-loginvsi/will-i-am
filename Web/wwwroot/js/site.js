(function () {
    var capsOn = false;
    var userNameEl = document.getElementById('Username');
    var pwdCapsEl = document.getElementById('PasswordCapWarn');

    var warnFunction = function () {
        if (capsOn) {
            this.classList.add('on');
            this.classList.remove('off');
        } else {
            this.classList.add('off');
            this.classList.remove('on');
        }
    };

    document.addEventListener('keydown', function (event) {
        capsOn = event.getModifierState && event.getModifierState('CapsLock');
        if (pwdCapsEl) {
            warnFunction.call(pwdCapsEl);
        }
    });

    if (userNameEl) {
        setTimeout(function () {
            userNameEl.focus();
        }, 500);
    }

})();