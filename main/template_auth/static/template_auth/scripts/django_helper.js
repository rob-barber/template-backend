'use strict';


/**
 * Retrieves the specified cookie from the document.
 * @param name: The name of the cookie to retrieve
 * */
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);

            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Retrieves the CSRF token from the document originally set by Django
 * */
function getDjangoCSRFToken() {
    return getCookie('csrftoken')
}