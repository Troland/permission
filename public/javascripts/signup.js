(function ($) {
  $(function () {
    $('#J_signForm').on('submit', function (e) {
      var username = $('#J_username').val(),
        password = $('#J_passwd').val(),
        params = {};

      params.username = username
      params.password = CryptoJS.AES.encrypt(password, 'iloveisolde').toString()

      $.post('/signup', params)
        .done(function (res) {
          console.log(res)
          if (res.code === '0') {
            window.location.href = '/views/login.html'
          } else {
            alert(res.errmessage)
          }
        })
      return false;
    })
  })
})(window.jQuery)
