// Mobile menu + tap-to-open dropdown
(function () {
  var nav = document.querySelector(".nav");
  var burger = document.querySelector(".burger");
  if (burger) burger.addEventListener("click", function () {
    var open = nav.classList.toggle("show");
    burger.setAttribute("aria-expanded", open);
  });
  document.querySelectorAll(".has-sub > button").forEach(function (b) {
    b.addEventListener("click", function (e) {
      e.stopPropagation();
      var li = b.parentElement;
      var open = li.classList.toggle("open");
      b.setAttribute("aria-expanded", open);
    });
  });
  document.addEventListener("click", function () {
    document.querySelectorAll(".has-sub.open").forEach(function (li) { li.classList.remove("open"); });
  });
})();
