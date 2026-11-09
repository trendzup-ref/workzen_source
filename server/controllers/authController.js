import jwt from 'jsonwebtoken';
import { timingSafeEqual } from 'node:crypto';
import { User } from '../models/User.js';
import {
  createEmailVerificationCode,
  hashEmailVerificationCode,
  sendEmailVerificationCode,
} from '../utils/emailVerification.js';

// Helper to generate token
const generateToken = (id) => {
  return jwt.sign(
    { id },
    process.env.JWT_SECRET || 'workzen_super_secret_jwt_key_2026_zenith_secure',
    { expiresIn: '30d' }
  );
};

const VERIFICATION_RESEND_INTERVAL_MS = 60 * 1000;
const MAX_VERIFICATION_ATTEMPTS = 5;
const ACTION_CODE_FIELDS = [
  '+recoveryCode',
  '+recoveryCodeExpiresAt',
  '+recoveryCodeLastSentAt',
  '+recoveryCodeAttempts',
  '+accountCode',
  '+accountCodeExpiresAt',
  '+accountCodeLastSentAt',
  '+accountCodeAttempts',
  '+accountCodePurpose',
  '+pendingEmail',
];

const isResendCoolingDown = (user) =>
  user.emailVerificationLastSentAt &&
  Date.now() - user.emailVerificationLastSentAt.getTime() < VERIFICATION_RESEND_INTERVAL_MS;

// @route   POST /api/auth/register
// @desc    Register a new user
export const register = async (req, res) => {
  try {
    const { name, email, password, role, department, designation, hourlyRate } = req.body;

    if (!name || typeof email !== 'string' || !email.trim() || !password) {
      return res.status(400).json({ success: false, message: 'Please provide name, email, and password' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await User.findOne({ email: normalizedEmail })
      .select('+emailVerificationCode +emailVerificationExpiresAt +emailVerificationLastSentAt +emailVerificationAttempts');
    if (existingUser) {
      if (existingUser.emailVerified !== false) {
        return res.status(400).json({ success: false, message: 'An account with this email already exists' });
      }

      if (isResendCoolingDown(existingUser)) {
        return res.status(429).json({ success: false, message: 'Please wait a minute before requesting another verification code.' });
      }

      const { code, expiresAt } = createEmailVerificationCode();
      await sendEmailVerificationCode(normalizedEmail, code);
      existingUser.emailVerificationCode = hashEmailVerificationCode(code);
      existingUser.emailVerificationExpiresAt = expiresAt;
      existingUser.emailVerificationAttempts = 0;
      existingUser.emailVerificationLastSentAt = new Date();
      await existingUser.save();
      return res.status(200).json({ success: true, verificationRequired: true, email: normalizedEmail });
    }

    const { code, expiresAt } = createEmailVerificationCode();
    await User.create({
      name,
      email: normalizedEmail,
      password,
      emailVerified: false,
      emailVerificationCode: hashEmailVerificationCode(code),
      emailVerificationExpiresAt: expiresAt,
      role: role || 'employee',
      department: department || 'Engineering',
      designation: designation || 'Specialist',
      hourlyRate: hourlyRate || 40,
    });

    await sendEmailVerificationCode(normalizedEmail, code);
    await User.updateOne(
      { email: normalizedEmail, emailVerified: false },
      { $set: { emailVerificationLastSentAt: new Date() } }
    );
    res.status(201).json({ success: true, verificationRequired: true, email: normalizedEmail });
  } catch (error) {
    console.error('Register error:', error);
    const status = error.message?.startsWith('Email verification is not configured') ? 503
      : error.message?.startsWith('Email delivery failed') ? 502
        : 500;
    res.status(status).json({
      success: false,
      message: error.message || 'Server error during registration',
      ...(status === 502 || status === 503
        ? { email: req.body.email?.trim().toLowerCase(), verificationRequired: true }
        : {}),
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;
    if (typeof email !== 'string' || !email.trim() || !/^\d{6}$/.test(code || '')) {
      return res.status(400).json({ success: false, message: 'Enter the six-digit verification code sent to your email.' });
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() })
      .select('+emailVerificationCode +emailVerificationExpiresAt +emailVerificationAttempts');
    const invalidCodeReason = !user ? 'account_not_found'
      : user.status === 'terminated' ? 'account_terminated'
        : user.emailVerified ? 'already_verified'
          : !user.emailVerificationCode ? 'code_not_stored'
            : !user.emailVerificationExpiresAt ? 'expiration_not_stored'
              : user.emailVerificationExpiresAt <= new Date() ? 'code_expired'
                : null;
    if (invalidCodeReason) {
      console.warn('Email verification code rejected:', { reason: invalidCodeReason });
      return res.status(400).json({ success: false, message: 'The verification code is invalid or expired. Request a new code.' });
    }

    const submittedHash = Buffer.from(hashEmailVerificationCode(code), 'hex');
    const savedHash = Buffer.from(user.emailVerificationCode, 'hex');
    if (submittedHash.length !== savedHash.length || !timingSafeEqual(submittedHash, savedHash)) {
      user.emailVerificationAttempts += 1;
      if (user.emailVerificationAttempts >= MAX_VERIFICATION_ATTEMPTS) {
        user.emailVerificationCode = undefined;
        user.emailVerificationExpiresAt = undefined;
        await user.save();
        return res.status(400).json({
          success: false,
          message: 'Too many incorrect codes. Request a new verification code.',
        });
      }
      await user.save();
      return res.status(400).json({
        success: false,
        message: `The verification code is incorrect. ${MAX_VERIFICATION_ATTEMPTS - user.emailVerificationAttempts} attempts remaining.`,
      });
    }

    user.emailVerified = true;
    user.emailVerificationCode = undefined;
    user.emailVerificationExpiresAt = undefined;
    user.emailVerificationAttempts = 0;
    await user.save();

    res.json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        designation: user.designation,
        hourlyRate: user.hourlyRate,
      },
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ success: false, message: 'Server error during email verification' });
  }
};

export const resendEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;
    if (typeof email !== 'string' || !email.trim()) {
      return res.status(400).json({ success: false, message: 'Please provide an email address.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail })
      .select('+emailVerificationCode +emailVerificationExpiresAt +emailVerificationLastSentAt +emailVerificationAttempts');
    if (!user || user.emailVerified) {
      return res.json({
        success: true,
        message: 'If an unverified account exists for this address, a new code has been sent.',
      });
    }

    if (isResendCoolingDown(user)) {
      return res.status(429).json({ success: false, message: 'Please wait a minute before requesting another verification code.' });
    }

    const { code, expiresAt } = createEmailVerificationCode();
    await sendEmailVerificationCode(normalizedEmail, code);
    user.emailVerificationCode = hashEmailVerificationCode(code);
    user.emailVerificationExpiresAt = expiresAt;
    user.emailVerificationAttempts = 0;
    user.emailVerificationLastSentAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: 'If an unverified account exists for this address, a new code has been sent.',
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    const status = error.message?.startsWith('Email verification is not configured') ? 503
      : error.message?.startsWith('Email delivery failed') ? 502
        : 500;
    res.status(status).json({ success: false, message: error.message || 'Unable to resend verification code.' });
  }
};

const isActionCodeCoolingDown = (sentAt) =>
  sentAt && Date.now() - sentAt.getTime() < VERIFICATION_RESEND_INTERVAL_MS;

const isActionCodeValid = (code, expiresAt, submittedCode) => {
  if (!code || !expiresAt || expiresAt <= new Date() || !/^\d{6}$/.test(submittedCode || '')) {
    return false;
  }

  const submittedHash = Buffer.from(hashEmailVerificationCode(submittedCode), 'hex');
  const savedHash = Buffer.from(code, 'hex');
  return submittedHash.length === savedHash.length && timingSafeEqual(submittedHash, savedHash);
};

const issueActionCode = async (user, { kind, purpose, recipient }) => {
  const isRecovery = kind === 'recovery';
  const sentAt = isRecovery ? user.recoveryCodeLastSentAt : user.accountCodeLastSentAt;
  if (isActionCodeCoolingDown(sentAt)) {
    return false;
  }

  const { code, expiresAt } = createEmailVerificationCode();
  await sendEmailVerificationCode(recipient, code);

  const now = new Date();
  if (isRecovery) {
    user.recoveryCode = hashEmailVerificationCode(code);
    user.recoveryCodeExpiresAt = expiresAt;
    user.recoveryCodeLastSentAt = now;
    user.recoveryCodeAttempts = 0;
  } else {
    user.accountCode = hashEmailVerificationCode(code);
    user.accountCodeExpiresAt = expiresAt;
    user.accountCodeLastSentAt = now;
    user.accountCodeAttempts = 0;
    user.accountCodePurpose = purpose;
  }
  await user.save();
  return true;
};

const clearRecoveryCode = (user) => {
  user.recoveryCode = undefined;
  user.recoveryCodeExpiresAt = undefined;
  user.recoveryCodeAttempts = 0;
};

const clearAccountCode = (user) => {
  user.accountCode = undefined;
  user.accountCodeExpiresAt = undefined;
  user.accountCodeAttempts = 0;
  user.accountCodePurpose = undefined;
  user.pendingEmail = undefined;
};

const createAuthResponse = (user) => ({
  success: true,
  token: generateToken(user._id),
  user: {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    department: user.department,
    designation: user.designation,
    hourlyRate: user.hourlyRate,
    avatar: user.avatar,
  },
});

export const requestRecoveryCode = async (req, res) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!email) {
      return res.status(400).json({ success: false, message: 'Please enter your account email.' });
    }

    const user = await User.findOne({
      email,
      status: { $ne: 'terminated' },
      $or: [{ emailVerified: true }, { emailVerified: { $exists: false } }],
    }).select(ACTION_CODE_FIELDS.join(' '));
    if (user) {
      const sent = await issueActionCode(user, {
        kind: 'recovery',
        recipient: user.email,
      });
      if (!sent) {
        return res.status(429).json({ success: false, message: 'Please wait a minute before requesting another code.' });
      }
    }

    res.json({
      success: true,
      message: 'If a verified account exists for this address, a sign-in code has been sent.',
    });
  } catch (error) {
    console.error('Recovery code request error:', error);
    const status = error.message?.startsWith('Email verification is not configured') ? 503
      : error.message?.startsWith('Email delivery failed') ? 502
        : 500;
    res.status(status).json({ success: false, message: error.message || 'Unable to send a sign-in code.' });
  }
};

export const verifyRecoveryCode = async (req, res) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const { code, newPassword } = req.body;
    if (!email || !/^\d{6}$/.test(code || '') ||
      (newPassword !== undefined && (typeof newPassword !== 'string' || newPassword.length < 6))) {
      return res.status(400).json({
        success: false,
        message: 'Enter the six-digit code and, if changing your password, a password with at least six characters.',
      });
    }

    const user = await User.findOne({
      email,
      status: { $ne: 'terminated' },
      $or: [{ emailVerified: true }, { emailVerified: { $exists: false } }],
    })
      .select(`+password ${ACTION_CODE_FIELDS.join(' ')}`);
    if (!user || !user.recoveryCode || !user.recoveryCodeExpiresAt ||
      user.recoveryCodeExpiresAt <= new Date()) {
      return res.status(400).json({ success: false, message: 'The code is invalid or expired. Request a new one.' });
    }

    if (!isActionCodeValid(user.recoveryCode, user.recoveryCodeExpiresAt, code)) {
      user.recoveryCodeAttempts += 1;
      if (user.recoveryCodeAttempts >= MAX_VERIFICATION_ATTEMPTS) {
        clearRecoveryCode(user);
      }
      await user.save();
      return res.status(400).json({
        success: false,
        message: user.recoveryCodeAttempts === 0
          ? 'Too many incorrect codes. Request a new one.'
          : `The code is incorrect. ${MAX_VERIFICATION_ATTEMPTS - user.recoveryCodeAttempts} attempts remaining.`,
      });
    }

    if (newPassword !== undefined) {
      user.password = newPassword;
    }
    clearRecoveryCode(user);
    await user.save();
    res.json(createAuthResponse(user));
  } catch (error) {
    console.error('Recovery code verification error:', error);
    res.status(500).json({ success: false, message: 'Unable to verify sign-in code.' });
  }
};

export const requestEmailChangeCode = async (req, res) => {
  try {
    const newEmail = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!newEmail || !/^\S+@\S+\.\S+$/.test(newEmail)) {
      return res.status(400).json({ success: false, message: 'Enter a valid new email address.' });
    }
    if (newEmail === req.user.email.toLowerCase()) {
      return res.status(400).json({ success: false, message: 'That is already your current email address.' });
    }
    if (await User.exists({ email: newEmail })) {
      return res.status(409).json({ success: false, message: 'An account with that email already exists.' });
    }

    const user = await User.findById(req.user.id).select(ACTION_CODE_FIELDS.join(' '));
    const sent = await issueActionCode(user, {
      kind: 'account',
      purpose: 'email',
      recipient: newEmail,
    });
    if (!sent) {
      return res.status(429).json({ success: false, message: 'Please wait a minute before requesting another code.' });
    }
    user.pendingEmail = newEmail;
    await user.save();
    res.json({ success: true, message: `A verification code was sent to ${newEmail}.` });
  } catch (error) {
    console.error('Email change code request error:', error);
    const status = error.message?.startsWith('Email verification is not configured') ? 503
      : error.message?.startsWith('Email delivery failed') ? 502
        : 500;
    res.status(status).json({ success: false, message: error.message || 'Unable to send email verification code.' });
  }
};

export const confirmEmailChange = async (req, res) => {
  try {
    const { code } = req.body;
    if (!/^\d{6}$/.test(code || '')) {
      return res.status(400).json({ success: false, message: 'Enter the six-digit code.' });
    }
    const user = await User.findById(req.user.id).select(ACTION_CODE_FIELDS.join(' '));
    if (!user || user.accountCodePurpose !== 'email' || !user.pendingEmail ||
      !user.accountCode || !user.accountCodeExpiresAt || user.accountCodeExpiresAt <= new Date()) {
      return res.status(400).json({ success: false, message: 'The code is invalid or expired. Request a new one.' });
    }
    if (!isActionCodeValid(user.accountCode, user.accountCodeExpiresAt, code)) {
      user.accountCodeAttempts += 1;
      if (user.accountCodeAttempts >= MAX_VERIFICATION_ATTEMPTS) clearAccountCode(user);
      await user.save();
      return res.status(400).json({ success: false, message: 'The code is incorrect or expired. Request a new one.' });
    }
    if (await User.exists({ email: user.pendingEmail, _id: { $ne: user._id } })) {
      clearAccountCode(user);
      await user.save();
      return res.status(409).json({ success: false, message: 'An account with that email already exists.' });
    }

    user.email = user.pendingEmail;
    user.emailVerified = true;
    clearAccountCode(user);
    await user.save();
    res.json({ success: true, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Email change confirmation error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ success: false, message: 'An account with that email already exists.' });
    }
    res.status(500).json({ success: false, message: 'Unable to update your email address.' });
  }
};

export const requestPasswordChangeCode = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(ACTION_CODE_FIELDS.join(' '));
    const sent = await issueActionCode(user, {
      kind: 'account',
      purpose: 'password',
      recipient: user.email,
    });
    if (!sent) {
      return res.status(429).json({ success: false, message: 'Please wait a minute before requesting another code.' });
    }
    user.pendingEmail = undefined;
    await user.save();
    res.json({ success: true, message: `A verification code was sent to ${user.email}.` });
  } catch (error) {
    console.error('Password change code request error:', error);
    const status = error.message?.startsWith('Email verification is not configured') ? 503
      : error.message?.startsWith('Email delivery failed') ? 502
        : 500;
    res.status(status).json({ success: false, message: error.message || 'Unable to send password verification code.' });
  }
};

export const confirmPasswordChange = async (req, res) => {
  try {
    const { code, newPassword } = req.body;
    if (!/^\d{6}$/.test(code || '') || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Enter the six-digit code and a password with at least six characters.' });
    }
    const user = await User.findById(req.user.id).select(`+password ${ACTION_CODE_FIELDS.join(' ')}`);
    if (!user || user.accountCodePurpose !== 'password' || !user.accountCode ||
      !user.accountCodeExpiresAt || user.accountCodeExpiresAt <= new Date()) {
      return res.status(400).json({ success: false, message: 'The code is invalid or expired. Request a new one.' });
    }
    if (!isActionCodeValid(user.accountCode, user.accountCodeExpiresAt, code)) {
      user.accountCodeAttempts += 1;
      if (user.accountCodeAttempts >= MAX_VERIFICATION_ATTEMPTS) clearAccountCode(user);
      await user.save();
      return res.status(400).json({ success: false, message: 'The code is incorrect or expired. Request a new one.' });
    }

    user.password = newPassword;
    clearAccountCode(user);
    await user.save();
    res.json({ success: true, message: 'Your password has been updated.' });
  } catch (error) {
    console.error('Password change confirmation error:', error);
    res.status(500).json({ success: false, message: 'Unable to update your password.' });
  }
};

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
    if (user.status === 'terminated') {
      return res.status(403).json({ success: false, message: 'This account has been terminated. Contact an administrator.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    if (user.emailVerified === false) {
      return res.status(403).json({ success: false, message: 'Please verify your email before signing in.' });
    }

    const token = generateToken(user._id);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        designation: user.designation,
        hourlyRate: user.hourlyRate,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: error.message || 'Server error during login' });
  }
};

// @route   GET /api/auth/me
// @desc    Get logged in user profile
export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        designation: user.designation,
        hourlyRate: user.hourlyRate,
        avatar: user.avatar,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// @route   GET /api/auth/users
// @desc    Get all users (for assigning to projects or viewing team)
export const getUsers = async (req, res) => {
  try {
    const { role } = req.query;
    const requestedStatus = req.query.status;
    if (requestedStatus === 'terminated' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Only administrators can view terminated team records.' });
    }

    const filter = requestedStatus === 'terminated'
      ? { status: 'terminated' }
      : { status: { $ne: 'terminated' } };
    if (role) filter.role = role;

    const users = await User.find(filter)
      .select('-password')
      .populate('terminatedBy', 'name')
      .sort({ name: 1 });
    res.json({ success: true, count: users.length, users });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const terminateUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select(ACTION_CODE_FIELDS.join(' '));
    if (!user) {
      return res.status(404).json({ success: false, message: 'Team member not found.' });
    }
    if (!['manager', 'employee'].includes(user.role)) {
      return res.status(400).json({ success: false, message: 'Only managers and employees can be terminated here.' });
    }
    if (user.status === 'terminated') {
      return res.status(409).json({ success: false, message: 'This team member is already terminated.' });
    }

    user.status = 'terminated';
    user.terminatedAt = new Date();
    user.terminatedBy = req.user.id;
    user.recoveryCode = undefined;
    user.recoveryCodeExpiresAt = undefined;
    user.recoveryCodeAttempts = 0;
    user.accountCode = undefined;
    user.accountCodeExpiresAt = undefined;
    user.accountCodeAttempts = 0;
    user.accountCodePurpose = undefined;
    user.pendingEmail = undefined;
    await user.save();

    res.json({ success: true, message: `${user.name} was terminated and moved to the terminated records.` });
  } catch (error) {
    console.error('Team member termination error:', error);
    res.status(500).json({ success: false, message: 'Unable to terminate this team member.' });
  }
};

export const restoreUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Team member not found.' });
    }
    if (!['manager', 'employee'].includes(user.role)) {
      return res.status(400).json({ success: false, message: 'Only terminated managers and employees can be restored here.' });
    }
    if (user.status !== 'terminated') {
      return res.status(409).json({ success: false, message: 'This team member is not terminated.' });
    }

    user.status = 'active';
    user.terminatedAt = null;
    user.terminatedBy = null;
    await user.save();

    res.json({ success: true, message: `${user.name} was restored to the active team.` });
  } catch (error) {
    console.error('Team member restoration error:', error);
    res.status(500).json({ success: false, message: 'Unable to restore this team member.' });
  }
};

// @route   PUT /api/auth/profile
// @desc    Update profile
export const updateProfile = async (req, res) => {
  try {
    const { name, department, designation, hourlyRate } = req.body;
    const user = await User.findById(req.user.id);

    if (name) user.name = name;
    if (department) user.department = department;
    if (designation) user.designation = designation;
    if (hourlyRate) user.hourlyRate = hourlyRate;

    await user.save();

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        designation: user.designation,
        hourlyRate: user.hourlyRate,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
