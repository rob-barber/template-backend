'use strict';

/**
 * A generic spinner object that controls the active state of any spinner
 * element.
 * */
class Spinner {

    constructor(spinnerElement) {

        // Make sure we are working with a jQuery object.
        if (spinnerElement instanceof jQuery) {
            this.spinner = spinnerElement;
        } else {
            this.spinner = $(spinnerElement);
        }

    }

    /**
     * Toggles the spinner to the specified view state
     * @param showSpinner: True if the spinner should be shown and animating, False otherwise
     * */
    toggleSpinner(showSpinner) {
        let isActive = this.spinner.hasClass('active');

        if (showSpinner && !isActive) {
            this.spinner.toggleClass('active');
        } else if (!showSpinner && isActive) {
            this.spinner.toggleClass('active');
        }
    }
}
