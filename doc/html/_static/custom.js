/*
 * Page loaded event
 *
 * Add ToC items unrolling handling.
 */
window.onload = function () {
	var sidebar_elt = document.getElementsByClassName('sphinxsidebar')[0];
	var li_elts = sidebar_elt.getElementsByTagName('li');
	for (var i=0; i < li_elts.length; i++) {
		var li_elt = li_elts[i];
		(function (li_elt) {
			li_elt.onclick = function (evt) {
				evt.stopPropagation();
				li_elt.classList.toggle('unrolled');
			};
		})(li_elt);
	}
}

/*
 * Internal links smooth scrolling
 */
$(document).ready(function() {
	$('.reference.internal, .headerlink').on('click', function() {
		var anchor = $(this).attr('href');
		if(/^#.+/.test(anchor) === true) {
			var speed = 750; // ms
			$('html, body').animate({
				scrollTop: $(anchor).offset().top
			}, speed );
		}
		return true; // propagate event
	});
});
