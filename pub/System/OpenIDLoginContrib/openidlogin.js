window.onload = (function(oldHandler) {
    return function() {
        var note = document.getElementsByClassName("native_toggle")[0];
        var mydiv = document.getElementsByClassName("native_credentials");
        var openid = document.getElementsByClassName("openid_accounts");
	for (var i = 0; i < mydiv.length; i++) {
            mydiv[i].style.display = 'none';
	}
  
        note.onclick = function() {
            note.style.display = 'none';
	    for (var i = 0; i < mydiv.length; i++) {
		mydiv[i].style.display = 'block';
	    }
	    for (var i = 0; i < openid.length; i++) {
		openid[i].style.display = 'none';
	    }
	    return false;
        };
        oldHandler && oldHandler();
    }})(window.onload);
