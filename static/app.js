document.addEventListener('DOMContentLoaded', function () {
  var v = document.getElementById('player');
  if (v && window.Plyr) {
    new Plyr(v, { controls: ['play-large','play','progress','current-time','duration','mute','volume','settings','pip','fullscreen'],
      settings: ['speed'], speed: { selected: 1, options: [0.5, 0.75, 1, 1.25, 1.5, 2] }, keyboard: { focused: true, global: true } });
    v.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  }
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
});
