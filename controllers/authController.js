const passport = require('passport');
const crypto = require('crypto');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const promisify = require('es6-promisify');
const mail = require('../handlers/mail');


exports.login = passport.authenticate('local', {
	failureRedirect: '/login',
	failureFlash: 'Failed Login!',
	successRedirect: '/',
	successFlash: 'You are successfully logged in 🎸'
});


exports.logout = (req, res) => {
	req.logout();
	req.flash('success', 'You are now logged out 👋 ✌️!!');
	res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
	// check if user is authenticated
	if(req.isAuthenticated()) {
		next(); //they're logged in!
		return;
	}
	req.flash('error', 'You must be logged in 😜 !!');
	res.redirect('/login');
};

exports.forgot = async (req, res) => {
	// 1. see if user exists
	const user = await User.findOne( { email: req.body.email });
	if(!user) {
		req.flash('error', 'A password has been reset has been email to you 🤔... maybe 😜! ');
		return res. redirect('/login');
	}

	// 2. set reset tokens and expiry on their account
	user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
	user.resetPasswordExpires = Date.now() + 3600000; // one hour from now
	await user.save();

	// 3. send email with the tokens
	const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;

	await mail.send({
		user,
		subject: 'Password Reset',
		resetURL,
		filename: 'password-reset',
	});

	req.flash('success', `You have been emailed a password reset link 👍 .`);

	// 4. redirect to login page
	res.redirect('/login');
};

exports.reset = async (req, res) => {
	//1. check if the token exists
	//2. check if the token is expired
	const user = await User.findOne({
		resetPasswordToken: req.params.token,
		resetPasswordExpires: { $gt: Date.now() }
	});
	if(!user) {
		req.flash('error', 'Password reset is invalid or has expired');
		return res.redirect('/login');
	}
	res.render('reset', {title: 'Reset Your Password'} );
};

exports.confirmedPasswords = (req, res, next) => {
	if (req.body.password === req.body['password-confirm']) {
		next(); //keep going!
		return;
	}
	req.flash('error', 'Passwords do not match 😡 !!');
	res.redirect('back');
};

exports.update = async (req, res) => {
	const user = await User.findOne({
		resetPasswordToken: req.params.token,
		resetPasswordExpires: { $gt: Date.now() }
	});

	if(!user) {
		req.flash('error', 'Password reset is invalid or has expired');
		return res.redirect('/login');
	}

	const setPassword = promisify(user.setPassword, user);
	await setPassword(req.body.password);

	user.resetPasswordToken = undefined;
	user.resetPasswordExpires = undefined;

	const updatedUser = await user.save();

	await req.login(updatedUser);

	req.flash('success', '💃 Wonderful! Your password has been reset!');

	res.redirect('/');
};
