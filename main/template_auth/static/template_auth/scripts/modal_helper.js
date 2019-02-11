'use strict';

/**
 * Shows a modal on screen.
 *
 * Note: The modal's HTML must already exist on screen for this function to work.
 *
 * @param titleText: The title for the modal to use
 * @param bodyText: The body text for the modal to use.
 * */
function showModal(titleText, bodyText) {

    let modal = $('#modal');
    let title = modal.find('#modal-title');
    let body = modal.find('#modal-body-text');

    title.text(titleText);
    body.text(bodyText);
    modal.modal('show');

}