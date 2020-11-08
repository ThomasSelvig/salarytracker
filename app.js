const express = require('express');
const pug = require('pug');
const morgan = require("morgan"); // logging
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const ejwt = require('express-jwt');
const cookie_parser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');

const path = require('path');
const public_folder = path.join(__dirname, 'public');
const static_folder = path.join(__dirname, 'static_priv');

var db = new sqlite3.Database(
	path.join(__dirname, "data.db"),
	sqlite3.OPEN_READWRITE,
	(err) => {
		if (err) {
			console.log("Database connection error");
		}
		else {
			console.log("Database connected");
		}
});
var SECRET_KEY = fs.readFileSync(`${__dirname}/JWT_SECRET.key`, "utf8").trim();

const app = express();
app.use(cookie_parser());
app.use("/p", express.static(public_folder));
app.use(morgan("common"));
app.use(bodyParser.urlencoded({extended: true}));
app.use(ejwt({
	secret: SECRET_KEY,
	algorithms: ["HS256"],
	getToken: (req) => {
		if (req.query && req.query.token) {
			return req.query.token;
		}
		else if (req.cookies && req.cookies.jwt) {
			try {
				return req.cookies.jwt.split(" ")[1].trim();
			}
			catch (e) {

			}
		}
		return null;
	}
}).unless({path: ["/login", "/register"]}));
app.use((err, req, res, next) => {
	if (err.name === "UnauthorizedError") {
		return res.redirect("/login");
	}
	next();
})

// date logic
const date_pattern = /^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[13-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$/;
const time_pattern = /^(2[0-3]|[01]?[0-9]):([0-5]?[0-9])$/;


function sign_in(un, res) {
	let payload = {"un": un};
	let token = jwt.sign(payload, SECRET_KEY, {expiresIn: 60*60*24, algorithm: "HS256"});
	res.cookie("jwt", `Bearer ${token}`, {maxAge: 1000*60*60*24, httpOnly: false});  // express-jwt can't read the jwt cookie if the httpOnly flag is set
	return token;
}


app.get("/login", (req, res) => {
	res.send(pug.renderFile(
		`${static_folder}/login.pug`
	))
});

app.post("/login", (req, res) => {
	if (!req.body.un || !req.body.pw) {
		return res.sendStatus(400);
	}
	let {un, pw} = req.body;
	db.get(
		"SELECT pw_salt FROM users WHERE un = ?",
		[un],
		(err, row) => {
			if (!err && row && row.pw_salt) {
				let pw_hash = crypto.createHash('sha256').update(pw + row.pw_salt).digest('hex');
				db.get("SELECT un FROM users WHERE un = ? AND pw_hash = ?", [un, pw_hash], (err, row) => {
					if (!err && row && row.un) {
						// user provided valid credentials, assign JWT token
						sign_in(row.un, res);
						res.redirect("/");
					}
					else {
						res.send(pug.renderFile(
							`${static_folder}/login.pug`,
							{alert: {
								type: "danger",
								text: "Go away!"
							}}
						));
					}
				});
			}
			else {
				res.send(pug.renderFile(
					`${static_folder}/login.pug`,
					{alert: {
						type: "danger",
						text: "Go away!"
					}}
				));
			}
		}
	);
});

app.get("/logout", (req, res) => {
	res.clearCookie("jwt");
	res.redirect("/");
});

app.post("/register", (req, res) => {
	if (!req.body.un || !req.body.pw) {
		return res.sendStatus(400);
	}
	let {un, pw} = req.body;
	if (!un.match(/^[a-zA-Z0-9_]{3,20}$/)) {
		return res.send(pug.renderFile(
			`${static_folder}/login.pug`,
			{alert: {
				type: "danger",
				text: "Username accepts letters (a-Z), (_), and digits (0-9). Must be between 3 and 20 chars."
			}}
		));
	}
	else if (!pw.match(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/)) {
		return res.send(pug.renderFile(
			`${static_folder}/login.pug`,
			{alert: {
				type: "danger",
				text: "Password: Minimum eight characters, at least one upper case English letter, one lower case English letter, one number and one special character"
			}}
		));
	}

	// valid un and pw
	var salt_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	var salt = "";
	for (var i = 0; i < 10; i++) {salt += salt_chars.charAt(Math.floor(Math.random()*salt_chars.length));}
	db.run(
		"INSERT INTO users(un, pw_hash, pw_salt) VALUES(?, ?, ?)",
		[
			un,
			crypto.createHash('sha256').update(pw + salt).digest('hex'),
			salt
		],
		(err) => {
			if (err) {
				console.log(err.message);
			}
			else {
				sign_in(un, res);
			}
		}
	);
	setTimeout(() => {
		return res.redirect("/");
	}, 250)
});


app.get("/", (req, res) => {
	res.send(pug.renderFile(
		`${static_folder}/index.pug`, {alert: {type: "info", text: `Logged in as <code>${req.user.un}</code>`}}
	));
});

app.post("/add_entry", (req, res) => {
	let {date, time, duration} = req.body;
	// validate input
	if (
		!date.match(date_pattern) ||
		!time.match(time_pattern) ||
		duration <= 0 ||
		duration > 20
	) {
		return res.sendStatus(400);
	}
	let [day, month, year] = date.split("/").map((val) => {return parseInt(val)});
	let [hour, min] = time.split(":").map((i) => {return parseFloat(i)});
	duration = parseFloat(duration);

	let date_obj = new Date(year, month - 1, day);
	let start_time_epoch_UTC = Date.UTC(year, month - 1, day) / 1000 + 60 * date_obj.getTimezoneOffset();
	// add "time"
	start_time_epoch_UTC += hour * 60 * 60 + min * 60;

	// TODO: check if it's a valid time frame (non-overlapping with other entries)
	// collision point 1: new entry starts before old entry and ends after old entry starts
	// collision point 2: new entry starts before old entry ends and ends after old entry ends

	db.get("SELECT username FROM salarylog WHERE username = ? AND start_time_epoch_UTC = ?", [
		req.user.un,
		start_time_epoch_UTC
	], (err, row) => {
		if (!row) {
			// nothing to overlap start_time_epoch_UTC
			// calculate pay
			var pay_period = [0, 6].includes(date_obj.getDay()) ? "weekend" : "weekday";
			db.get(
				"SELECT hourly_pay FROM salary_periods WHERE period_name = ?",
				[pay_period],
				(err, row) => {
					// add to table
					db.run(
						"INSERT INTO salarylog( \
							start_time_epoch_UTC, \
							username, \
							start_date, \
							start_time, \
							hours, \
							pay_period, \
							earned) \
							VALUES(?, ?, ?, ?, ?, ?, ?)",
						[
							start_time_epoch_UTC,
							req.user.un,
							date,
							time,
							duration,
							pay_period, // pay period
							row.hourly_pay * duration // earned
						],
						(err) => {
							if (err) {
								res.send(pug.renderFile(
									`${static_folder}/index.pug`,
									{alert: {type: "danger", text: err.message}}
								));
								res.end();
							}
						}
					);
				}
			);
		}
		else if (row && row.username) {
			return res.send(pug.renderFile(
				`${static_folder}/index.pug`,
				{alert: {type: "danger", text: "Overlapping entries, ignoring."}}
			))
		}
	})

	setTimeout(() => {
		if (!res.finished) {
			res.send(pug.renderFile(
				`${static_folder}/index.pug`,
				{alert: {type: "success", text: "Successfully logged entry!"}}
			));
		}
	}, 250);
});

app.get("/view", (req, res) => {
	let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
	let split = req.query.tf.split("/")
	if (split.length != 2) {
		return res.sendStatus(400);
	}
	let month = split[0].toLowerCase().slice(0, 3);
	let year = parseInt(split[1]);
	if (!months.includes(month) || year < 1900 || year > 2100) {
		return res.sendStatus(400);
	}
	//let month_UTC = Date.UTC(2020, months.indexOf(month), 1) / 1000 + 60 * new Date(2020, months.indexOf(month), 1).getTimezoneOffset();

	// TODO: make month->UTC conversions more readable (and add support for more than 2020)
	db.all(
		"SELECT start_date, start_time, hours, pay_period, earned FROM salarylog WHERE \
		? < start_time_epoch_UTC AND start_time_epoch_UTC < ? AND username = ?",
		[
			Date.UTC(year, months.indexOf(month), 1) / 1000 + 60 * new Date(2020, months.indexOf(month), 1).getTimezoneOffset(),
			Date.UTC(months.indexOf(month) < months.length - 1 ? year : year + 1, (months.indexOf(month) + 1) % months.length, 1) / 1000 + 60 * new Date(months.indexOf(month) < months.length - 1 ? year : year + 1, (months.indexOf(month) + 1) % months.length, 1).getTimezoneOffset(),
			req.user.un
		],
		(err, rows) => {
			let table_rows = rows.map((row, i) => {return [
				row.start_date,
				row.start_time,
				row.hours,
				row.pay_period,
				row.earned / row.hours,
				row.earned
			];});
			res.send(pug.renderFile(
				`${static_folder}/database.pug`,
				{rows: table_rows}
			));
		}
	);
});

app.listen(80, "localhost", () => {
	console.log("Listening");
});
