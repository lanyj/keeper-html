var AUTHENTICATION_TOKEN = "__token";
var restUrl = "http://127.0.0.1/keeper";
var webUrl = window.location.origin + "/keeper-html/";

function setCookie(name,value) { 
    var exp = new Date(); 
    exp.setTime(exp.getTime() + 15 * 60 * 1000); 
    document.cookie = name + "="+ escape (value) + ";expires=" + exp.toGMTString(); 
}
function getCookie(name) { 
    var arr,reg=new RegExp("(^| )"+name+"=([^;]*)(;|$)");
 
    if(arr=document.cookie.match(reg))
        return unescape(arr[2]); 
    else 
        return null; 
} 
function deleteCookie(name) { 
    var exp = new Date(); 
    exp.setTime(exp.getTime() - 1); 
    var cval=getCookie(name); 
    if(cval!=null) 
        document.cookie= name + "="+cval+";expires="+exp.toGMTString(); 
}

var token = getCookie("__token");
if(isObj(getCookie("__token"))) {
	refresh(false);
}

function htmlEncode(value){
  return $('<div/>').text(value).html();
}

function htmlDecode(value){
  return $('<div/>').html(value).text();
}
	
function getQueryString(name) {
	var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
	var r = window.location.search.substr(1).match(reg);
	if (r != null)
		return unescape(r[2]);
	return null;
}

function getUrlDomin(url) {
	if(url.indexOf('/') != -1) {
		url = url.split("/")[0];
	}
	if(url.indexOf('?') != -1) {
		url = url.split("?")[0];
	}
	if(url.indexOf("http://") == -1 && url.indexOf("https://") == -1) {
		url = "https://" + url;
	}
	return url;
}

function passwordEncoder(password) {
	return CryptoJS.SHA256("UKeeper-password-" + password).toString();
}

function aesDecrypt(str, password) {
	var decrypted = CryptoJS.AES.decrypt(plaintext, password); 
	return decrypted;
}

function getResponse(ret) {
	return ret['response'];
}

function isObj(obj) {
	return obj && obj !== 'null' && obj !== 'undefined';
}

function alertError(msg) {
	swal("错误", msg, "error");
}

function checkForAlertMsgError(from, ret) {
	if(isObj(ret)) {
		if(ret['msg'] == "email or password invalidated.") {
			swal(from, "用户名或密码错误", "error");
			return true;
		} else if(ret['msg'] == "mail is not validated.") {
			swal(from, "邮箱不合法", "error");
			return true;
		} else if(ret['msg'] == "password length cannot less than 6 letters") {
			swal(from, "密码强度不够", "error");
			return true;
		} else if(ret['msg'] == "mail is alerdy in use.") {
			swal(from, "该邮箱已被使用", "error");
			return true;
		} else if(ret['msg'] == "user not found." || ret['msg'] == "mail is not in use.") {
			swal(from, "用户名不存在", "error");
		}
	}
	return false;
}

function getToken(ret) {
	deleteCookie("__token");
	setCookie('__token', ret[AUTHENTICATION_TOKEN]);
	return ret[AUTHENTICATION_TOKEN];
}

function refresh(async) {
	if(!isObj(async)) {
		async = true;
	}
	if(isObj(token)) {
		$.ajax({
			url: restUrl + "/user/refresh",
			type: "POST",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			data: {
				__token: token
			},
			async: async
		}).done(function(ret) {
			ret = getResponse(ret);
			if(ret['success'] == true) {
				token = getToken(ret);
				$('#index-login-button').html(htmlEncode(ret['email']));
				$('#index-login-button').attr("href", "#");
				$('#index-register-button').html("登出").attr("href", "login.html");
				$('#index-register-button').unbind();
				$('#index-register-button').click(function() {
					deleteCookie("__token");
					token = null;
					window.location.href = "login.html";
				})
			} else {
				deleteCookie("__token");
				token = null;
				$('#index-login-button').html(htmlEncode("登录")).attr("href", "login.html");
				$('#index-register-button').html("注册").attr("href", "register.html");
				$('#index-register-button').unbind();
			}
		}).fail(function() {{
			deleteCookie("__token");
			$('#index-login-button').html(htmlEncode("登录"));
			$('#index-login-button').attr("href", "login.html");
			$('#index-register-button').html("注册").attr("href", "register.html");
			$('#index-register-button').unbind();
			token = null;
		}})
	}
}

// 十分钟刷新一次
$(function(){
	refresh();
	setInterval(refresh, 1000 * 60 * 10);
})

function login(email, password) {
	$.ajax({
		url : restUrl + "/user/login",
		type : "GET",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data : {
			email : email,
			password : passwordEncoder(password)
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if (ret['success'] == true) {
			var token = getToken(ret);
			loginSuccess(token);
		} else {
			loginFailed(ret);
		}
	}).fail(function() {
		loginFailed();
	})
}

function loginSuccess(token) {
	window.location.href = "index.html";
}

function loginFailed(ret) {
	if(!checkForAlertMsgError("用户登录", ret)) {
		swal("用户登录", "未知错误", "error");
	}
}

function register(email, password, password2) {
	if (email.length < 3) {
		alertError("邮箱不合法");
		return;
	}
	if (password != password2) {
		alertError("密码不一致");
		return;
	}
	if (password.length < 6) {
		alertError("密码长度不应该小于6");
		return;
	}
	$.ajax({
		url : restUrl + "/user/register",
		type : "POST",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data : {
			email : email,
			password : passwordEncoder(password),
			redirectUrl : webUrl + "success.html"
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if (ret['success'] == true) {
			registerSuccess(ret);
		} else {
			registerFailed(ret);
		}
	}).fail(function() {
		registerFailed();
	})
}

function registerSuccess(ret) {
	swal("用户注册", "用户激活链接已通过邮件发送给您，请注意查收您的邮件。", "success")
		.then(function (value){
			window.location.href = "index.html";
		})
}

function registerFailed(ret) {
	if(!checkForAlertMsgError("用户注册", ret)) {
		swal("用户登录", "未知错误", "error");
	}
}

function forget(email, password, password2) {
	if (email.length < 3) {
		alertError("邮箱不合法");
		return;
	}
	if (password != password2) {
		alertError("密码不一致");
		return;
	}
	if (password.length < 6) {
		alertError("密码长度不应该小于6");
		return;
	}
	$.ajax({
		url : restUrl + "/user/forget",
		type : "POST",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data : {
			email : email,
			password : passwordEncoder(password),
			redirectUrl : webUrl + "success.html"
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if (ret['success'] == true) {
			forgetSuccess(ret);
		} else {
			forgetFailed(ret);
		}
	}).fail(function(ret) {
		forgetFailed();
	})
}

function forgetSuccess(ret) {
	swal("密码重置", "密码重置链接已通过邮件发送给您，请注意查收您的邮件。", "success")
		.then(function (value) {
			window.location.href = "index.html";
		})
}

function forgetFailed(ret) {
	if(checkForAlertMsgError("密码重置", ret)) {
		return;
	}
	swal("密码重置", "重置失败", "error");
}

$('#login_submit').click(function() {
	login($('#login_email').val(), $('#login_password').val());
})

$('#register_submit').click(
		function() {
			register($('#register_email').val(), $('#register_password').val(),
					$('#register_password2').val());
		})

$('#forget_submit').click(function() {
	forget($('#forget_email').val(), $('#forget_password').val(),
					$('#forget_password2').val())
})

/** ************************************************************************************** */
/** ************************************************************************************** */

function getPasswordContent(password) {
	var html = '<div class="col-md-6 col-lg-4 item" index-password-list-item="';
	html += htmlEncode(password['id']);
	html += '"><div class="box"><p class="description">';
	html += '<b>' + htmlEncode(password['url']) + '</b><hr/>' + htmlEncode(password['content']);
	html += '</p></div><div class="author"><img class="rounded-circle" src="' + getUrlDomin(password['url']) + '/favicon.ico" alt="' + htmlEncode(password['url']) + '">';
	html += '<h5 class="name">';
	html += htmlEncode(password['username']);
	html += '</h5><p class="title">';
	html += htmlEncode(password['password']);
	html += '</p></div></div>';
	return html;
}

function getPasswords() {
	if(!isObj(token)) {
		return;
	}
	$.ajax({
		url: restUrl + "/password/list",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			__token: token
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			getPasswordsSuccess(ret);
		} else {
			getPasswordsFailed(ret);
		}
	}).fail(function() {
		getPasswordsFailed();
	})
}

function getPassword(id) {
	var password;
	$.ajax({
		url: restUrl + "/password/list/" + htmlDecode(id),
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			__token: token
		},
		async: false
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			password = getPasswordSuccess(ret);
		} else {
			getPasswordFailed(ret);
		}
	}).fail(function() {
		getPasswordFailed();
	})
	return password;
}

var INDEX_PASSWORD_LIST_ITEM_ADD_NEW = '<div class="col-md-6 col-lg-4 item text-success bg-dark" index-password-list-item="addone">'
									 + '<div class="box bg-dark"><p class="description">添加新密码</p>'
									 + '</div><div class="author"><img class="rounded-circle" src="assets/img/add.png">'
									 + '<h5 class="name">添加新密码</h5><p class="title"></p>'
									 + '</div></div>';

function getPasswordsSuccess(ret) {
	var ps = $('#index_password_list');
	var vs = ret['value'];
	var html = "";
	for(var i in vs) {
		var p = vs[i];
		html += getPasswordContent(p);
	}
	html += INDEX_PASSWORD_LIST_ITEM_ADD_NEW;
	ps.html(html);
	
	$('[index-password-list-item]').unbind();
	$('[index-password-list-item]').click(function(e) {
		e.preventDefault();
		var id = $(this).attr('index-password-list-item');
		passwordEdit(id)
	})
}

function getPasswordsFailed(ret) {
	if(!checkForAlertMsgError("密码拉取", ret)) {
		swal("密码拉取", "未知错误", "error");
	}
}

function getPasswordSuccess(ret) {
	return ret['value'];
}

function getPasswordsFailed(ret) {
	if(!checkForAlertMsgError("密码拉取", ret)) {
		swal("密码拉取", "未知错误", "error");
	}
}

function showPassword(password) {
	if(isObj(password)) {
		var html = '<article class="card-body">'
			 + '<h4 class="card-title mb-4 mt-1">密码信息</h4><form><div class="form-group">'
			 + '<input id="index-password-edit-id" type="hidden" value="' + password['id'] + '"/>'
			 + '<label>网站地址</label> <input name="" class="form-control" id="index-password-edit-url" type="text" '
			 + 'value="' + htmlEncode(password['url']) + '">'
			 + '</div><div class="form-group"><label>描述</label> <input name="" '
			 + 'class="form-control" id="index-password-edit-content" '
			 + 'value="' + htmlEncode(password['content']) + '" '
			 + 'type="text"></div><div class="form-group"><label>用户名</label> <input name="" '
			 + 'class="form-control" id="index-password-edit-username" '
			 + 'value="' + htmlEncode(password['username']) + '" '
			 + 'type="text"></div><div class="form-group"><label>密码</label> '
			 + '<input class="form-control" id="index-password-edit-password" '
			 + 'value="' + htmlEncode(password['password']) + '" '
			 + 'type="text"></div></form></article>';
		return html;
	} else {
		var html = '<article class="card-body">'
			 + '<h4 class="card-title mb-4 mt-1">密码信息</h4><form><div class="form-group">'
			 + '<input id="index-password-edit-id" type="hidden" value="" />'
			 + '<label>网站地址</label> <input name="" class="form-control" placeholder="网站地址" id="index-password-edit-url" type="text">'
			 + '</div><div class="form-group"><label>描述</label> <input name="" '
			 + 'class="form-control" placeholder="网站描述" id="index-password-edit-content" '
			 + 'type="text"></div><div class="form-group"><label>用户名</label> <input name="" '
			 + 'class="form-control" placeholder="用户名" id="index-password-edit-username" '
			 + 'type="text"></div><div class="form-group"><label>密码</label> '
			 + '<input class="form-control" placeholder="密码" id="index-password-edit-password" '
			 + 'type="text"></div></form></article>';
		return html;
	}
}

function passwordEdit(id) {
	$("#index-password-edit-container").html('<div id="index-password-edit"></div>');
	
	if(id == "addone") {
		$('#index-password-edit').html(showPassword());
		swal("新增密码", {
		    content: document.getElementById("index-password-edit"),
		    buttons: true
		})
		.then(function (value) {
			if(value) {
				var url = $('#index-password-edit-url').val();
				var content = $('#index-password-edit-content').val();
				var username = $('#index-password-edit-username').val();
				var password = $('#index-password-edit-password').val();
				passwordSave(url, content, username, password);
			}
		})
	} else {
		$('#index-password-edit').html(showPassword(getPassword(id)));
		swal("修改密码", {
		    content: document.getElementById("index-password-edit"),
		    buttons: {
		        cancel: "取消",
		        del: {
		          text: "删除",
		          value: "del",
		        },
		        confirm: {
			          text: "确认",
			          value: "confirm",
			    }
		      }
		})
		.then(function (value) {
			switch(value) {
			case "confirm": {
				var id = $('#index-password-edit-id').val();
				var url = $('#index-password-edit-url').val();
				var content = $('#index-password-edit-content').val();
				var username = $('#index-password-edit-username').val();
				var password = $('#index-password-edit-password').val();
				passwordUpdate(id, url, content, username, password);
				break;
			}
			case "del": {
				var id = $('#index-password-edit-id').val();
				passwordDelete(id);
				break;
			}
			}
		})
	}
}

function passwordSave(url, content, username, password) {
	$.ajax({
		url: restUrl + "/password/save",
		type: "POST",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			url: url,
			content: content,
			username: username,
			password: password,
			__token: token
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			passwordEditSuccess();
		} else {
			passwordEditFailed(ret);
		}
	}).fail(function() {
		passwordEditFailed();
	})
}

function passwordUpdate(id, url, content, username, password) {
	$.ajax({
		url: restUrl + "/password/update",
		type: "POST",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			id: id,
			url: url,
			content: content,
			username: username,
			password: password,
			__token: token
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			passwordEditSuccess();
		} else {
			passwordEditFailed(ret);
		}
	}).fail(function() {
		passwordEditFailed();
	})	
}

function passwordEditSuccess() {
	swal("密码更新", "更新完成", "success");
	getPasswords();
}

function passwordEditFailed(ret) {
	if(checkForAlertMsgError("密码更新", ret)) {
		return;
	}
	swal("密码更新", "未知错误", "error");
}

function passwordDelete(id) {
	$.ajax({
		url: restUrl + "/password/delete/" + htmlEncode(id),
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			__token: token
		},
		type: "POST"
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			swal("密码删除", "密码已删除", "success");
			getPasswords();
		} else {
			if(!checkForAlertMsgError("密码删除", ret)) {
				swal("密码删除", "删除失败", "error");
			}
		}
	}).fail(function() {
		if(!checkForAlertMsgError("密码删除")) {
			swal("密码删除", "删除失败", "error");
		}
	})
}

$(function() {
	getPasswords();
})

function getPasswordsByUrl(url) {
	if(!isObj(token)) {
		return;
	}
	$.ajax({
		url: restUrl + "/password/like",
		contentType: "application/x-www-form-urlencoded; charset=utf-8",
		data: {
			url: url,
			__token: token
		}
	}).done(function(ret) {
		ret = getResponse(ret);
		if(ret['success'] == true) {
			getPasswordsSuccess(ret);
		} else {
			getPasswordsFailed(ret);
		}
	}).fail(function() {
		getPasswordsFailed();
	})
}

$('#index_search_button').click(function() {
	var search = $('#index-search-field').val();
	if(search == "") {
		getPasswords();
	} else {
		getPasswordsByUrl(search);
	}
});

