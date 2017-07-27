/**
 * login 模块
 */
(function (window, $) {
  $(function () {
    $('#J_loginForm').on('submit', function() {
      var userName = $('#J_userName').val(),
        passwd = $('#J_passwd').val(),
        params = {};

      params.username = userName
      params.password =  CryptoJS.AES.encrypt(passwd, 'iloveisolde').toString()

      $.post('/login', params)
        .done(function (res) {
          console.log(res)
          if (res.code === '0') {
            window.localStorage.setItem('token', res.token)
            window.location.href = '/views/index.html'
          }
        })

      return false;
    })
  })
})(window, jQuery,)
