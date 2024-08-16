/*
const Mailjet = require("node-mailjet");

const mailjet = Mailjet.apiConnect(
  "695efbae2a56620a381597566ba6c8b8",
  "4db7f378f98c13bfbe2a48db8119c5d9",
);

function sendActivationEmail(
  recipientEmail,
  recipientName,
  activationCode,
  userName,
) {
  const request = mailjet.post("send", { version: "v3.1" }).request({
    Messages: [
      {
        From: {
          Email: "liquemgames@gmail.com",
          Name: "Liquem Games Support",
        },
        To: [
          {
            Email: recipientEmail,
            Name: recipientName,
          },
        ],
        Subject: "Your Skilled Royale 2FA Code",
        TextPart: `Hello ${userName},

Your code is ${activationCode}. Enter this code to enable 2FA.

Thank you,
Liquem Games Support`,
        // CustomID: "AccVerify",
      },
    ],
  });

  return request;
}

// Example usage:
sendActivationEmail("liam.heizmann@gmail.com", "Liquem", 567577, "Ange")
  .then((result) => {
    console.log("E-mail sent to " + "me");
  })
  .catch((err) => {
    console.log(err);
  });

*/
