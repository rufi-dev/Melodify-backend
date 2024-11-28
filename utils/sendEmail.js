import nodemailer from "nodemailer";
import hbs from "nodemailer-express-handlebars";
import path from "path";

const sendEmail = async (
  subject,
  send_to,
  sent_from,
  reply_to,
  template,
  username,
  link
) => {
  // Create EmailTransporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
    // logger: true, // Enable logging
    // debug: true, // Enable debugging
  });

  const handlebarOptions = {
    viewEngine: {
      extName: ".handlebars",
      partialsDir: path.resolve("./views"),
      defaultLayout: false,
    },
    viewPath: path.resolve("./views"),
    extName: ".handlebars",
  };

  transporter.use("compile", hbs(handlebarOptions));

  //Options for sending email
  const options = {
    from: sent_from,
    to: send_to,
    replyTo: reply_to,
    template: template,
    subject,
    context: {
      username,
      link,
    },
  };

  //Send Email
  console.log(options);
  transporter.sendMail(options, function (err, info) {
    if (err) {
      console.log(err);
    } else {
      console.log(info);
    }
  });
};

export { sendEmail };
