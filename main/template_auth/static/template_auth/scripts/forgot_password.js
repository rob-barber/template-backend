'use strict';

let forgotPasswordUrl = '';
let spinner = null;
let submit = null;

$(document).ready(function() {

    spinner = new Spinner($('#submit-spinner'));
    submit = $('#submit');

});

/**
 * Takes the rendered Django url and sets the submit function on the
 * form.
 * @param formUrl: The form url to use in the submit request.
 * */
function setupForgotPasswordForm(formUrl) {
    forgotPasswordUrl = formUrl;
    $('#forgot-password-form').submit(submitForgotPasswordForm);
}

/**
 * Submission form for the forgot password form.
 *
 * @param event: The form event
 * */
function submitForgotPasswordForm(event) {

    event.preventDefault();

    let data = $(this).serialize(); // The data to send to the server
    let csrftoken = this.elements.csrfmiddlewaretoken.value;
    let email = this.elements.email.value;

    if (email === '') {
        showModal('Missing Data', 'Please enter your email to recover your account.');
        return;
    }

    toggleActivityState(true);

    // Send the form data to the server
    $.ajax({
        type: 'POST',
        url: forgotPasswordUrl,
        data: data,
        headers: {
            'X-CSRFToken': csrftoken
        },
        success: function(responseData) {
            toggleActivityState(false);

            showModal(
                'Success',
                `A recovery email will be sent to ${email} if the account exists.`);

        },
        error: function(xhr, status, err) {
            toggleActivityState(false);

            showModal(
                'Issue recovering account',
                'If the problem persists please contact your administrator.'
            )
        }
    });

    return false;

}

/**
 * Toggles the visual state of the view when there is any network activity
 * @param activity: True when there is network activity, false otherwise.
 * */
function toggleActivityState(activity) {
    spinner.toggleSpinner(activity);
    submit.prop('disabled', activity);

    if (activity) {
        submit.textColor = submit.css('color'); // Empty to show spinner on top of button
        submit.css('color', 'transparent');
    } else {
        submit.css('color', submit.textColor);
    }

}

