
import { createHash, randomInt } from 'node:crypto';
import { Resend } from 'resend';

const CODE_EXPIRATION_MINUTES = 10;

const getEmailSettings = () => {
  const API_KEY = process.env.RESEND_API_KEY?.trim();
  const EMAIL_FROM =
    process.env.EMAIL_FROM?.trim() || 'onboarding@resend.dev';

  const missingSettings = [
    !API_KEY && 'RESEND_API_KEY',
  ].filter(Boolean);

  return {
    settings: {
      API_KEY,
      EMAIL_FROM,
    },
    missingSettings,
  };
};

export const isEmailVerificationConfigured = () =>
  getEmailSettings().missingSettings.length === 0;

export const createEmailVerificationCode = () => ({
  code: String(randomInt(100000, 1000000)),
  expiresAt: new Date(
    Date.now() + CODE_EXPIRATION_MINUTES * 60 * 1000
  ),
});

export const hashEmailVerificationCode = (code) =>
  createHash('sha256').update(code).digest('hex');

export const sendEmailVerificationCode = async (email, code) => {
  const { settings, missingSettings } = getEmailSettings();

  if (missingSettings.length) {
    throw new Error(
      `Email verification is not configured. Set ${missingSettings.join(' and ')} in Render environment variables.`
    );
  }

  const resend = new Resend(settings.API_KEY);

  try {
    const { data, error } = await resend.emails.send({
      from: settings.EMAIL_FROM,
      to: email,
      subject: 'Your Workzen verification code',
      text: `Your Workzen verification code is ${code}. It expires in ${CODE_EXPIRATION_MINUTES} minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Workzen Verification</h2>
          <p>Your verification code is:</p>
          <h1 style="letter-spacing: 5px;">${code}</h1>
          <p>This code expires in ${CODE_EXPIRATION_MINUTES} minutes.</p>
          <p>If you did not request this code, please ignore this email.</p>
        </div>
      `,
    });

    if (error) {
      console.error('Resend email delivery error:', error);
      throw new Error('Resend email delivery failed');
    }

    console.log('Verification email accepted:', data?.id);

    return data;

  } catch (error) {
    console.error('Email delivery failed:', error.message);
    throw new Error('Email delivery failed. Check your Resend API configuration.');
  }
};
