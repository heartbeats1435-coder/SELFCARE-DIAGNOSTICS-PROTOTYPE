/**
 * ============================================================
 * SELFCARE DIAGNOSTICS
 * AUTHENTICATION MODULE
 * File: assets/gs/auth.gs
 * ============================================================
 *
 * Handles:
 * - Login with User ID / Mobile / Email
 * - Registration OTP
 * - Account creation
 * - Password reset OTP
 * - Password reset
 * - Session creation
 * - Logout
 * - Server-side DOB → Age calculation
 *
 * Passwords are hashed before being stored.
 * OTP values are never returned to the frontend.
 * ============================================================
 */


/* ============================================================
 * LOGIN
 * ============================================================ */

function authLogin_(payload, requestId) {

  var identifier =
    normalizeIdentifier_(
      payload.identifier
    );

  var password =
    String(
      payload.password || ''
    );

  if (!identifier) {

    return authError_(
      'Please enter your User ID, mobile number or email.'
    );

  }

  if (!password) {

    return authError_(
      'Please enter your password.'
    );

  }

  var user =
    findUserByIdentifier_(
      identifier
    );

  if (!user) {

    recordLoginAttempt_(
      identifier,
      false,
      requestId
    );

    return authError_(
      'Invalid login credentials.'
    );

  }

  /*
   * Check account status.
   */

  var status =
    String(
      user.Status || 'ACTIVE'
    ).toUpperCase();

  if (
    status !== 'ACTIVE'
  ) {

    return authError_(
      'Your account is not active. Please contact Selfcare Diagnostics.'
    );

  }


  /*
   * Check temporary login lock.
   */

  if (
    isUserLoginLocked_(
      user
    )
  ) {

    return authError_(
      'Too many unsuccessful attempts. Please try again later.'
    );

  }


  /*
   * Verify password.
   */

  var storedHash =
    String(
      user.PasswordHash || ''
    );

  var storedSalt =
    String(
      user.PasswordSalt || ''
    );

  if (
    !storedHash ||
    !storedSalt
  ) {

    return authError_(
      'Invalid login credentials.'
    );

  }

  var validPassword =
    verifyPassword_(
      password,
      storedHash,
      storedSalt
    );

  if (!validPassword) {

    recordLoginAttempt_(
      identifier,
      false,
      requestId
    );

    registerFailedLogin_(
      user
    );

    return authError_(
      'Invalid login credentials.'
    );

  }


  /*
   * Successful login.
   */

  clearFailedLogin_(
    user
  );

  var token =
    createSessionToken_();

  var session =
    createSession_(
      user,
      token
    );

  var loginTime =
    getServerDateTime_();

  updateUserLoginInfo_(
    user,
    loginTime
  );

  recordLoginAttempt_(
    identifier,
    true,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Login successful.',

    token:
      token,

    sessionToken:
      token,

    user:
      buildSafeUserObject_(
        user,
        loginTime
      ),

    data: {

      user:
        buildSafeUserObject_(
          user,
          loginTime
        ),

      session:
        session

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * REGISTRATION OTP
 * ============================================================ */

function authSendRegistrationOtp_(
  payload,
  requestId
) {

  var mobile =
    normalizeMobile_(
      payload.mobile
    );

  var name =
    cleanName_(
      payload.name
    );


  if (
    !isValidMobile_(mobile)
  ) {

    return authError_(
      'Please enter a valid 10-digit mobile number.'
    );

  }

  if (!name) {

    return authError_(
      'Please enter your name.'
    );

  }


  /*
   * Existing mobile cannot register again.
   */

  var existing =
    findUserByMobile_(
      mobile
    );

  if (existing) {

    return authError_(
      'An account already exists with this mobile number. Please login instead.'
    );

  }


  /*
   * Rate-limit OTP requests.
   */

  if (
    isOtpRateLimited_(
      mobile,
      'REGISTRATION'
    )
  ) {

    return authError_(
      'Please wait before requesting another OTP.'
    );

  }


  var otp =
    generateOtp_();

  var otpHash =
    hashOtp_(
      otp
    );

  var now =
    getServerNow_();

  var expires =
    new Date(
      now.getTime() +
      (
        SCD_CONFIG.AUTH.OTP_EXPIRY_SECONDS *
        1000
      )
    );


  /*
   * Store only the OTP hash.
   */

  saveOtp_({

    purpose:
      'REGISTRATION',

    mobile:
      mobile,

    otpHash:
      otpHash,

    createdAt:
      formatServerDateTime_(
        now
      ),

    expiresAt:
      formatServerDateTime_(
        expires
      ),

    attempts:
      0,

    verified:
      false,

    requestId:
      requestId

  });


  /*
   * Send OTP.
   */

  var sent =
    sendOtpSms_(
      mobile,
      otp,
      'registration'
    );


  if (!sent) {

    return authError_(
      'Unable to send OTP right now. Please try again.'
    );

  }


  logAuthEvent_(
    'REGISTRATION_OTP_SENT',
    mobile,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'OTP sent successfully.',

    data: {

      mobile:
        maskMobile_(
          mobile
        ),

      expiresIn:
        SCD_CONFIG.AUTH.OTP_EXPIRY_SECONDS

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * CREATE ACCOUNT
 * ============================================================ */

function authCreateAccount_(
  payload,
  requestId
) {

  var name =
    cleanName_(
      payload.name
    );

  var dob =
    normalizeDob_(
      payload.dob
    );

  var mobile =
    normalizeMobile_(
      payload.mobile
    );

  var email =
    normalizeEmail_(
      payload.email
    );

  var bloodGroup =
    normalizeBloodGroup_(
      payload.bloodGroup
    );

  var password =
    String(
      payload.password || ''
    );

  var otp =
    cleanOtp_(
      payload.otp
    );


  /* ----------------------------------------------------------
   * Validation
   * ---------------------------------------------------------- */

  if (!name) {

    return authError_(
      'Name is required.'
    );

  }

  if (!dob) {

    return authError_(
      'A valid date of birth is required.'
    );

  }

  if (
    !isValidMobile_(
      mobile
    )
  ) {

    return authError_(
      'Please enter a valid mobile number.'
    );

  }

  if (
    email &&
    !isValidEmail_(
      email
    )
  ) {

    return authError_(
      'Please enter a valid email address.'
    );

  }

  if (
    !isValidPassword_(
      password
    )
  ) {

    return authError_(
      'Password must be at least 8 characters.'
    );

  }

  if (
    !/^[0-9]{6}$/.test(
      otp
    )
  ) {

    return authError_(
      'Please enter the 6-digit OTP.'
    );

  }


  /*
   * Re-check uniqueness immediately before creation.
   * This prevents duplicate accounts when two requests
   * arrive close together.
   */

  if (
    findUserByMobile_(
      mobile
    )
  ) {

    return authError_(
      'An account already exists with this mobile number.'
    );

  }


  if (
    email &&
    findUserByEmail_(
      email
    )
  ) {

    return authError_(
      'An account already exists with this email address.'
    );

  }


  /*
   * Verify registration OTP.
   */

  var otpResult =
    verifyStoredOtp_(
      mobile,
      otp,
      'REGISTRATION'
    );

  if (
    !otpResult.valid
  ) {

    return authError_(
      otpResult.message ||
      'Invalid or expired OTP.'
    );

  }


  /*
   * Server-side age calculation.
   *
   * Browser-provided age values are NOT trusted.
   */

  var age =
    calculateAgeServer_(
      dob,
      getServerNow_()
    );


  if (!age) {

    return authError_(
      'Unable to calculate age from the date of birth.'
    );

  }


  /*
   * Generate unique SCD User ID.
   */

  var userId =
    generateUniqueUserId_();


  /*
   * Secure password hash.
   */

  var salt =
    generatePasswordSalt_();

  var passwordHash =
    hashPassword_(
      password,
      salt
    );


  var createdAt =
    getServerDateTime_();


  /*
   * Create user object.
   */

  var user = {

    UserID:
      userId,

    Name:
      name,

    DOB:
      dob,

    AgeYears:
      age.years,

    AgeMonths:
      age.months,

    AgeDays:
      age.days,

    Mobile:
      mobile,

    Email:
      email,

    BloodGroup:
      bloodGroup,

    PasswordHash:
      passwordHash,

    PasswordSalt:
      salt,

    LoginType:
      'SIGNUP',

    Role:
      SCD_CONFIG.USER.DEFAULT_ROLE,

    Status:
      SCD_CONFIG.USER.DEFAULT_STATUS,

    CreatedAt:
      createdAt,

    UpdatedAt:
      createdAt,

    LastLoginAt:
      '',

    FailedLoginAttempts:
      0,

    LockedUntil:
      '',

    PhoneVerified:
      true,

    EmailVerified:
      false,

    AgeUpdatedAt:
      createdAt

  };


  /*
   * Store user.
   */

  insertUser_(
    user
  );


  /*
   * Create initial session so the frontend can
   * automatically open the customer dashboard.
   */

  var token =
    createSessionToken_();

  var session =
    createSession_(
      user,
      token
    );


  /*
   * Mark OTP as consumed.
   */

  markOtpUsed_(
    otpResult.otpRow
  );


  logAuthEvent_(
    'ACCOUNT_CREATED',
    userId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Account created successfully.',

    token:
      token,

    sessionToken:
      token,

    userId:
      userId,

    UserID:
      userId,

    user:
      buildSafeUserObject_(
        user,
        createdAt
      ),

    data: {

      userId:
        userId,

      UserID:
        userId,

      user:
        buildSafeUserObject_(
          user,
          createdAt
        ),

      session:
        session

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * PASSWORD RESET OTP
 * ============================================================ */

function authSendPasswordResetOtp_(
  payload,
  requestId
) {

  var mobile =
    normalizeMobile_(
      payload.mobile
    );


  if (
    !isValidMobile_(
      mobile
    )
  ) {

    return authError_(
      'Please enter a valid 10-digit mobile number.'
    );

  }


  var user =
    findUserByMobile_(
      mobile
    );


  /*
   * Do not reveal whether an account exists.
   *
   * However, the frontend can still show a generic
   * success message.
   */

  if (!user) {

    logAuthEvent_(
      'PASSWORD_RESET_UNKNOWN_MOBILE',
      maskMobile_(mobile),
      requestId
    );

    return {

      success: true,

      status: 'success',

      message:
        'If an account exists with this mobile number, an OTP has been sent.',

      data: {

        mobile:
          maskMobile_(
            mobile
          ),

        expiresIn:
          SCD_CONFIG.AUTH.OTP_EXPIRY_SECONDS

      },

      requestId:
        requestId

    };

  }


  if (
    isOtpRateLimited_(
      mobile,
      'PASSWORD_RESET'
    )
  ) {

    return authError_(
      'Please wait before requesting another OTP.'
    );

  }


  var otp =
    generateOtp_();

  var otpHash =
    hashOtp_(
      otp
    );

  var now =
    getServerNow_();

  var expires =
    new Date(
      now.getTime() +
      (
        SCD_CONFIG.AUTH.OTP_EXPIRY_SECONDS *
        1000
      )
    );


  saveOtp_({

    purpose:
      'PASSWORD_RESET',

    mobile:
      mobile,

    otpHash:
      otpHash,

    createdAt:
      formatServerDateTime_(
        now
      ),

    expiresAt:
      formatServerDateTime_(
        expires
      ),

    attempts:
      0,

    verified:
      false,

    requestId:
      requestId

  });


  var sent =
    sendOtpSms_(
      mobile,
      otp,
      'password reset'
    );


  if (!sent) {

    return authError_(
      'Unable to send OTP right now. Please try again.'
    );

  }


  logAuthEvent_(
    'PASSWORD_RESET_OTP_SENT',
    maskMobile_(mobile),
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'If an account exists with this mobile number, an OTP has been sent.',

    data: {

      mobile:
        maskMobile_(
          mobile
        ),

      expiresIn:
        SCD_CONFIG.AUTH.OTP_EXPIRY_SECONDS

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * VERIFY PASSWORD RESET OTP
 * ============================================================ */

function authVerifyPasswordResetOtp_(
  payload,
  requestId
) {

  var mobile =
    normalizeMobile_(
      payload.mobile
    );

  var otp =
    cleanOtp_(
      payload.otp
    );


  if (
    !isValidMobile_(
      mobile
    )
  ) {

    return authError_(
      'Invalid mobile number.'
    );

  }

  if (
    !/^[0-9]{6}$/.test(
      otp
    )
  ) {

    return authError_(
      'Please enter the 6-digit OTP.'
    );

  }


  var result =
    verifyStoredOtp_(
      mobile,
      otp,
      'PASSWORD_RESET'
    );


  if (
    !result.valid
  ) {

    return authError_(
      result.message ||
      'Invalid or expired OTP.'
    );

  }


  /*
   * Keep OTP marked as verified until reset_password
   * consumes it.
   */

  markOtpVerified_(
    result.otpRow
  );


  logAuthEvent_(
    'PASSWORD_RESET_OTP_VERIFIED',
    maskMobile_(mobile),
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'OTP verified successfully.',

    data: {

      mobile:
        maskMobile_(
          mobile
        ),

      verified:
        true

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * RESET PASSWORD
 * ============================================================ */

function authResetPassword_(
  payload,
  requestId
) {

  var mobile =
    normalizeMobile_(
      payload.mobile
    );

  var otp =
    cleanOtp_(
      payload.otp
    );

  var password =
    String(
      payload.password || ''
    );


  if (
    !isValidMobile_(
      mobile
    )
  ) {

    return authError_(
      'Invalid mobile number.'
    );

  }

  if (
    !/^[0-9]{6}$/.test(
      otp
    )
  ) {

    return authError_(
      'Invalid OTP.'
    );

  }

  if (
    !isValidPassword_(
      password
    )
  ) {

    return authError_(
      'Password must be at least 8 characters.'
    );

  }


  var otpResult =
    verifyStoredOtp_(
      mobile,
      otp,
      'PASSWORD_RESET',
      true
    );


  if (
    !otpResult.valid
  ) {

    return authError_(
      otpResult.message ||
      'Invalid or expired OTP.'
    );

  }


  var user =
    findUserByMobile_(
      mobile
    );


  if (!user) {

    return authError_(
      'Unable to reset password.'
    );

  }


  /*
   * Generate a completely new salt.
   */

  var salt =
    generatePasswordSalt_();

  var passwordHash =
    hashPassword_(
      password,
      salt
    );


  updateUserPassword_(
    user,
    passwordHash,
    salt
  );


  /*
   * Invalidate all previous sessions.
   */

  invalidateUserSessions_(
    user.UserID
  );


  /*
   * Mark OTP consumed.
   */

  markOtpUsed_(
    otpResult.otpRow
  );


  logAuthEvent_(
    'PASSWORD_RESET_COMPLETED',
    user.UserID,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Password updated successfully. Please login again.',

    data: {

      userId:
        user.UserID

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * LOGOUT
 * ============================================================ */

function authLogout_(
  payload,
  requestId
) {

  var token =
    String(
      payload.token ||
      payload.sessionToken ||
      ''
    ).trim();


  if (!token) {

    return {

      success: true,

      status: 'success',

      message:
        'Logged out successfully.',

      requestId:
        requestId

    };

  }


  var session =
    findSessionByToken_(
      token
    );


  if (session) {

    invalidateSession_(
      token
    );


    logAuthEvent_(
      'LOGOUT',
      session.UserID || '',
      requestId
    );

  }


  return {

    success: true,

    status: 'success',

    message:
      'Logged out successfully.',

    requestId:
      requestId

  };

}


/* ============================================================
 * USER HELPERS
 * ============================================================ */

function normalizeIdentifier_(
  value
) {

  var text =
    String(
      value || ''
    ).trim();

  if (
    /^[+0-9\s-]+$/.test(
      text
    )
  ) {

    var mobile =
      normalizeMobile_(
        text
      );

    if (
      isValidMobile_(
        mobile
      )
    ) {

      return mobile;

    }

  }


  if (
    text.indexOf('@') !== -1
  ) {

    return normalizeEmail_(
      text
    );

  }


  return text.toUpperCase();

}


function cleanName_(
  value
) {

  var name =
    String(
      value || ''
    )
      .replace(/\s+/g, ' ')
      .trim();

  if (
    name.length > 100
  ) {

    name =
      name.substring(
        0,
        100
      );

  }

  return name;

}


function normalizeMobile_(
  value
) {

  var mobile =
    String(
      value || ''
    )
      .replace(/\D/g, '');


  if (
    mobile.length === 12 &&
    mobile.substring(0, 2) ===
      SCD_CONFIG.COUNTRY_CODE
  ) {

    mobile =
      mobile.substring(2);

  }


  if (
    mobile.length === 11 &&
    mobile.charAt(0) === '0'
  ) {

    mobile =
      mobile.substring(1);

  }


  return mobile;

}


function normalizeEmail_(
  value
) {

  return String(
    value || ''
  )
    .trim()
    .toLowerCase();

}


function normalizeBloodGroup_(
  value
) {

  var blood =
    String(
      value || ''
    )
      .trim()
      .toUpperCase();

  var allowed = [
    'A+',
    'A-',
    'B+',
    'B-',
    'AB+',
    'AB-',
    'O+',
    'O-'
  ];

  if (
    blood &&
    allowed.indexOf(
      blood
    ) === -1
  ) {

    return '';

  }

  return blood;

}


function cleanOtp_(
  value
) {

  return String(
    value || ''
  )
    .replace(/\D/g, '')
    .substring(0, 6);

}


/* ============================================================
 * VALIDATION
 * ============================================================ */

function isValidMobile_(
  mobile
) {

  return (
    /^[6-9][0-9]{9}$/.test(
      String(
        mobile || ''
      )
    )
  );

}


function isValidEmail_(
  email
) {

  return (
    SCD_CONFIG.VALIDATION.EMAIL_REGEX
      .test(
        String(
          email || ''
        )
      )
  );

}


function isValidPassword_(
  password
) {

  var value =
    String(
      password || ''
    );

  return (
    value.length >=
      SCD_CONFIG.AUTH.PASSWORD_MIN_LENGTH &&
    value.length <=
      SCD_CONFIG.AUTH.PASSWORD_MAX_LENGTH
  );

}


/* ============================================================
 * DOB
 * ============================================================ */

function normalizeDob_(
  value
) {

  var text =
    String(
      value || ''
    ).trim();

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(
      text
    )
  ) {

    return '';

  }


  var parts =
    text.split('-');

  var year =
    Number(parts[0]);

  var month =
    Number(parts[1]);

  var day =
    Number(parts[2]);


  var date =
    new Date(
      year,
      month - 1,
      day
    );


  if (
    date.getFullYear() !== year ||
    date.getMonth() !==
      month - 1 ||
    date.getDate() !== day
  ) {

    return '';

  }


  var today =
    getServerNow_();


  /*
   * Future DOB is invalid.
   */

  if (
    date > today
  ) {

    return '';

  }


  /*
   * Prevent unrealistic DOB.
   */

  var minimumYear =
    today.getFullYear() - 120;


  if (
    year < minimumYear
  ) {

    return '';

  }


  return (
    year +
    '-' +
    String(month)
      .padStart(2, '0') +
    '-' +
    String(day)
      .padStart(2, '0')
  );

}


/**
 * Authoritative server-side age calculation.
 */
function calculateAgeServer_(
  dobString,
  referenceDate
) {

  if (!dobString) {
    return null;
  }

  var parts =
    String(
      dobString
    ).split('-');

  if (
    parts.length !== 3
  ) {
    return null;
  }

  var dob =
    new Date(
      Number(parts[0]),
      Number(parts[1]) - 1,
      Number(parts[2])
    );

  var today =
    referenceDate instanceof Date
      ? new Date(
          referenceDate.getTime()
        )
      : new Date();


  if (
    isNaN(
      dob.getTime()
    ) ||
    dob > today
  ) {

    return null;

  }


  var years =
    today.getFullYear() -
    dob.getFullYear();

  var months =
    today.getMonth() -
    dob.getMonth();

  var days =
    today.getDate() -
    dob.getDate();


  if (
    days < 0
  ) {

    months--;

    var previousMonth =
      new Date(
        today.getFullYear(),
        today.getMonth(),
        0
      );

    days +=
      previousMonth.getDate();

  }


  if (
    months < 0
  ) {

    years--;

    months += 12;

  }


  return {

    years:
      years,

    months:
      months,

    days:
      days

  };

}


/* ============================================================
 * SAFE USER OBJECT
 * ============================================================ */

function buildSafeUserObject_(
  user,
  loginTime
) {

  return {

    userId:
      user.UserID || '',

    UserID:
      user.UserID || '',

    name:
      user.Name || '',

    mobile:
      user.Mobile || '',

    email:
      user.Email || '',

    dob:
      user.DOB || '',

    ageYears:
      Number(
        user.AgeYears || 0
      ),

    ageMonths:
      Number(
        user.AgeMonths || 0
      ),

    ageDays:
      Number(
        user.AgeDays || 0
      ),

    bloodGroup:
      user.BloodGroup || '',

    loginType:
      user.LoginType || '',

    role:
      user.Role || 'CUSTOMER',

    status:
      user.Status || 'ACTIVE',

    phoneVerified:
      Boolean(
        user.PhoneVerified
      ),

    emailVerified:
      Boolean(
        user.EmailVerified
      ),

    createdAt:
      user.CreatedAt || '',

    updatedAt:
      user.UpdatedAt || '',

    lastLoginAt:
      loginTime ||
      user.LastLoginAt ||
      ''

  };

}


/* ============================================================
 * USER ID
 * ============================================================ */

function generateUniqueUserId_() {

  for (
    var attempt = 0;
    attempt < 20;
    attempt++
  ) {

    var timestamp =
      Utilities.formatDate(
        getServerNow_(),
        SCD_CONFIG.TIMEZONE,
        'yyMMddHHmmss'
      );

    var random =
      Math.floor(
        1000 +
        Math.random() * 9000
      );


    var id =
      SCD_CONFIG.USER_ID_PREFIX +
      timestamp +
      random;


    if (
      !findUserById_(
        id
      )
    ) {

      return id;

    }

  }


  throw new Error(
    'Unable to generate a unique User ID.'
  );

}


/* ============================================================
 * OTP GENERATION
 * ============================================================ */

function generateOtp_() {

  var min =
    SCD_CONFIG.SECURITY.OTP_RANDOM_MIN;

  var max =
    SCD_CONFIG.SECURITY.OTP_RANDOM_MAX;

  return String(
    Math.floor(
      min +
      Math.random() *
      (
        max -
        min +
        1
      )
    )
  );

}


/**
 * Hash OTP using security.gs.
 */
function hashOtp_(
  otp
) {

  return hashSecret_(
    String(
      otp || ''
    )
  );

}


/* ============================================================
 * SMS
 * ============================================================ */

/**
 * Development-safe SMS function.
 *
 * In production connect this function to your approved
 * SMS provider / API.
 *
 * IMPORTANT:
 * OTP is logged only in DEVELOPMENT for testing.
 * It must never be logged in production.
 */
function sendOtpSms_(
  mobile,
  otp,
  purpose
) {

  var environment =
    String(
      SCD_CONFIG.ENVIRONMENT ||
      'development'
    ).toLowerCase();


  /*
   * Production:
   *
   * Replace this block with your SMS provider API.
   *
   * Do NOT return the OTP to the frontend.
   */

  if (
    environment ===
    'production'
  ) {

    /*
     * TODO:
     * Integrate approved SMS provider here.
     *
     * Example:
     *
     * var response = UrlFetchApp.fetch(...);
     *
     * return response.getResponseCode() === 200;
     */

    throw new Error(
      'SMS provider is not configured for production.'
    );

  }


  /*
   * Development mode:
   * Write a development-only log.
   */

  console.log(
    '[SELFCARE DEVELOPMENT OTP]',
    purpose,
    maskMobile_(mobile),
    otp
  );


  return true;

}


/* ============================================================
 * MISC
 * ============================================================ */

function maskMobile_(
  mobile
) {

  var value =
    String(
      mobile || ''
    );

  if (
    value.length !== 10
  ) {

    return '**********';

  }

  return (
    value.substring(0, 2) +
    '******' +
    value.substring(8)
  );

}


function authError_(
  message
) {

  return {

    success: false,

    status: 'error',

    message:
      String(
        message ||
        'Request could not be completed.'
      )

  };

}


/* ============================================================
 * LOGIN ATTEMPT PLACEHOLDERS
 * ============================================================ *
 *
 * database.gs / security.gs provide the actual storage
 * functions. These wrappers keep auth.gs independent.
 */

function recordLoginAttempt_(
  identifier,
  successful,
  requestId
) {

  if (
    typeof writeAuditLog_ ===
    'function'
  ) {

    writeAuditLog_({

      Event:
        successful
          ? 'LOGIN_SUCCESS'
          : 'LOGIN_FAILED',

      UserID:
        '',

      Identifier:
        String(
          identifier || ''
        ).substring(0, 100),

      RequestID:
        requestId || '',

      CreatedAt:
        getServerDateTime_()

    });

  }

}


function registerFailedLogin_(
  user
) {

  if (
    typeof updateFailedLogin_ ===
    'function'
  ) {

    updateFailedLogin_(
      user
    );

  }

}


function clearFailedLogin_(
  user
) {

  if (
    typeof resetFailedLogin_ ===
    'function'
  ) {

    resetFailedLogin_(
      user
    );

  }

}


function updateUserLoginInfo_(
  user,
  loginTime
) {

  if (
    typeof updateUserLastLogin_ ===
    'function'
  ) {

    updateUserLastLogin_(
      user.UserID,
      loginTime
    );

  }

}


function logAuthEvent_(
  eventName,
  reference,
  requestId
) {

  if (
    typeof writeAuditLog_ !==
    'function'
  ) {

    return;

  }

  writeAuditLog_({

    Event:
      eventName,

    UserID:
      reference || '',

    RequestID:
      requestId || '',

    CreatedAt:
      getServerDateTime_()

  });

}
/* ============================================================
 * SELFCARE DIAGNOSTICS
 * ADMIN + TECHNICIAN AUTHENTICATION
 * Add this section at the END of auth.gs
 * ============================================================ */


/* ============================================================
 * INITIAL ADMIN SETUP
 * ============================================================ */

/**
 * Run this function ONCE manually from Apps Script.
 *
 * It creates:
 * admin@selfcare
 *
 * with ADMIN role.
 *
 * The password is hashed before storage.
 */
function setupInitialAdmin() {

  var adminId =
    String(
      SCD_CONFIG.ADMIN.DEFAULT_ID
    ).trim().toLowerCase();

  var adminPassword =
    String(
      SCD_CONFIG.ADMIN.DEFAULT_PASSWORD
    );

  if (
    !adminId ||
    !adminPassword
  ) {

    throw new Error(
      'Initial admin configuration is missing.'
    );

  }


  if (
    !isValidPassword_(
      adminPassword
    )
  ) {

    throw new Error(
      'Initial admin password does not meet password requirements.'
    );

  }


  var existing =
    findUserByIdentifier_(
      adminId
    );


  /*
   * If admin already exists,
   * do not create a duplicate.
   */

  if (existing) {

    /*
     * Make sure existing account is ADMIN.
     */

    if (
      String(
        existing.Role || ''
      ).toUpperCase() !==
      SCD_CONFIG.ROLES.ADMIN
    ) {

      throw new Error(
        'The configured admin ID already belongs to another user.'
      );

    }


    return {

      success: true,

      status: 'success',

      message:
        'Admin account already exists.',

      userId:
        existing.UserID

    };

  }


  var salt =
    generatePasswordSalt_();

  var passwordHash =
    hashPassword_(
      adminPassword,
      salt
    );


  var now =
    getServerDateTime_();


  var adminUser = {

    UserID:
      adminId,

    Name:
      SCD_CONFIG.ADMIN.DEFAULT_NAME,

    DOB:
      '',

    AgeYears:
      '',

    AgeMonths:
      '',

    AgeDays:
      '',

    Mobile:
      '',

    Email:
      adminId,

    BloodGroup:
      '',

    PasswordHash:
      passwordHash,

    PasswordSalt:
      salt,

    LoginType:
      SCD_CONFIG.ADMIN.LOGIN_TYPE,

    Role:
      SCD_CONFIG.ROLES.ADMIN,

    Status:
      SCD_CONFIG.ADMIN.STATUS,

    CreatedAt:
      now,

    UpdatedAt:
      now,

    LastLoginAt:
      '',

    FailedLoginAttempts:
      0,

    LockedUntil:
      '',

    PhoneVerified:
      false,

    EmailVerified:
      false,

    AgeUpdatedAt:
      ''

  };


  insertUser_(
    adminUser
  );


  logAuthEvent_(
    'ADMIN_CREATED',
    adminId,
    'ADMIN-SETUP'
  );


  return {

    success: true,

    status: 'success',

    message:
      'Initial admin account created successfully.',

    userId:
      adminId,

    role:
      SCD_CONFIG.ROLES.ADMIN

  };

}


/* ============================================================
 * ADMIN SESSION VALIDATION
 * ============================================================ */

function requireAdminSession_(
  payload
) {

  var token =
    String(
      payload.token ||
      payload.sessionToken ||
      ''
    ).trim();


  if (!token) {

    throw new Error(
      'Admin session is required.'
    );

  }


  var session =
    findSessionByToken_(
      token
    );


  if (!session) {

    throw new Error(
      'Invalid or expired session.'
    );

  }


  /*
   * Session status.
   */

  var sessionStatus =
    String(
      session.Status ||
      'ACTIVE'
    ).toUpperCase();


  if (
    sessionStatus !==
    'ACTIVE'
  ) {

    throw new Error(
      'Session is no longer active.'
    );

  }


  /*
   * Expiry.
   */

  if (
    session.ExpiresAt
  ) {

    var expiry =
      new Date(
        session.ExpiresAt
      );

    if (
      !isNaN(
        expiry.getTime()
      ) &&
      expiry.getTime() <=
        new Date().getTime()
    ) {

      throw new Error(
        'Session has expired.'
      );

    }

  }


  /*
   * Get actual user.
   */

  var user =
    findUserById_(
      session.UserID
    );


  if (!user) {

    throw new Error(
      'Admin account was not found.'
    );

  }


  var role =
    String(
      user.Role || ''
    ).toUpperCase();


  if (
    role !==
    SCD_CONFIG.ROLES.ADMIN
  ) {

    throw new Error(
      'Administrator permission required.'
    );

  }


  var status =
    String(
      user.Status || ''
    ).toUpperCase();


  if (
    status !==
    'ACTIVE'
  ) {

    throw new Error(
      'Admin account is not active.'
    );

  }


  return {

    token:
      token,

    session:
      session,

    user:
      user

  };

}


/* ============================================================
 * TECHNICIAN ID
 * ============================================================ */

function generateUniqueTechnicianId_() {

  for (
    var attempt = 0;
    attempt < 30;
    attempt++
  ) {

    var timestamp =
      Utilities.formatDate(

        getServerNow_(),

        SCD_CONFIG.TIMEZONE,

        'yyMMddHHmmss'

      );


    var random =
      Math.floor(
        100 +
        Math.random() *
        900
      );


    var technicianId =
      SCD_CONFIG.TECHNICIAN.ID_PREFIX +
      timestamp +
      random;


    /*
     * database.gs will provide this function.
     */

    if (
      typeof findTechnicianById_ ===
      'function'
    ) {

      if (
        !findTechnicianById_(
          technicianId
        )
      ) {

        return technicianId;

      }

    } else {

      /*
       * Database technician lookup will be
       * added in the next database.gs.
       */

      return technicianId;

    }

  }


  throw new Error(
    'Unable to generate a unique Technician ID.'
  );

}


/* ============================================================
 * ADMIN CREATE TECHNICIAN
 * ============================================================ */

function adminCreateTechnician_(
  payload,
  requestId
) {

  /*
   * Only ADMIN can call this.
   */

  var admin =
    requireAdminSession_(
      payload
    );


  var name =
    cleanTechnicianName_(
      payload.technicianName ||
      payload.name
    );


  var age =
    Number(
      payload.age
    );


  var mobile =
    normalizeMobile_(
      payload.mobile
    );


  var email =
    normalizeEmail_(
      payload.email
    );


  var address =
    cleanTechnicianAddress_(
      payload.address
    );


  var password =
    String(
      payload.password || ''
    );


  var photoBase64 =
    String(
      payload.photoBase64 || ''
    );


  var photoMimeType =
    String(
      payload.photoMimeType || ''
    )
      .trim()
      .toLowerCase();


  var photoName =
    cleanPhotoName_(
      payload.photoName
    );


  /* ----------------------------------------------------------
   * VALIDATION
   * ---------------------------------------------------------- */

  if (!name) {

    return authError_(
      'Technician name is required.'
    );

  }


  if (
    !isValidTechnicianAge_(
      age
    )
  ) {

    return authError_(
      'Please enter a valid technician age.'
    );

  }


  if (
    !isValidMobile_(
      mobile
    )
  ) {

    return authError_(
      'Please enter a valid 10-digit mobile number.'
    );

  }


  if (
    email &&
    !isValidEmail_(
      email
    )
  ) {

    return authError_(
      'Please enter a valid email address.'
    );

  }


  if (
    !isValidPassword_(
      password
    )
  ) {

    return authError_(
      'Technician password must be at least 8 characters.'
    );

  }


  if (
    address.length >
    SCD_CONFIG.TECHNICIAN.MAX_ADDRESS_LENGTH
  ) {

    return authError_(
      'Technician address is too long.'
    );

  }


  /*
   * Check mobile duplicate.
   */

  if (
    findUserByMobile_(
      mobile
    )
  ) {

    return authError_(
      'An account already exists with this mobile number.'
    );

  }


  /*
   * Check email duplicate.
   */

  if (
    email &&
    findUserByEmail_(
      email
    )
  ) {

    return authError_(
      'An account already exists with this email address.'
    );

  }


  /*
   * Photo validation.
   */

  if (
    photoBase64
  ) {

    if (
      !SCD_CONFIG.PHOTO_UPLOAD.ENABLED
    ) {

      return authError_(
        'Technician photo upload is disabled.'
      );

    }


    if (
      !isAllowedTechnicianPhotoType_(
        photoMimeType
      )
    ) {

      return authError_(
        'Unsupported technician photo format.'
      );

    }


    /*
     * Base64 size estimate.
     */

    var estimatedBytes =
      Math.floor(
        (
          photoBase64.length *
          3
        ) / 4
      );


    if (
      !isAllowedTechnicianPhotoSize_(
        estimatedBytes
      )
    ) {

      return authError_(
        'Technician photo must be 5 MB or smaller.'
      );

    }

  }


  /* ----------------------------------------------------------
   * CREATE IDS
   * ---------------------------------------------------------- */

  var technicianId =
    generateUniqueTechnicianId_();


  var userId =
    generateUniqueUserId_();


  /* ----------------------------------------------------------
   * PASSWORD HASH
   * ---------------------------------------------------------- */

  var salt =
    generatePasswordSalt_();


  var passwordHash =
    hashPassword_(
      password,
      salt
    );


  var now =
    getServerDateTime_();


  /* ----------------------------------------------------------
   * CREATE USER ACCOUNT
   * ---------------------------------------------------------- */

  var technicianUser = {

    UserID:
      userId,

    Name:
      name,

    DOB:
      '',

    AgeYears:
      age,

    AgeMonths:
      0,

    AgeDays:
      0,

    Mobile:
      mobile,

    Email:
      email,

    BloodGroup:
      '',

    PasswordHash:
      passwordHash,

    PasswordSalt:
      salt,

    LoginType:
      SCD_CONFIG.TECHNICIAN.LOGIN_TYPE,

    Role:
      SCD_CONFIG.ROLES.TECHNICIAN,

    Status:
      SCD_CONFIG.TECHNICIAN.DEFAULT_STATUS,

    CreatedAt:
      now,

    UpdatedAt:
      now,

    LastLoginAt:
      '',

    FailedLoginAttempts:
      0,

    LockedUntil:
      '',

    PhoneVerified:
      false,

    EmailVerified:
      false,

    AgeUpdatedAt:
      now

  };


  insertUser_(
    technicianUser
  );


  /* ----------------------------------------------------------
   * PHOTO
   * ---------------------------------------------------------- */

  var photoData = {

    photoUrl:
      '',

    photoFileId:
      ''

  };


  if (
    photoBase64
  ) {

    photoData =
      uploadTechnicianPhoto_({

        technicianId:
          technicianId,

        technicianName:
          name,

        photoBase64:
          photoBase64,

        photoMimeType:
          photoMimeType,

        photoName:
          photoName

      });

  }


  /* ----------------------------------------------------------
   * TECHNICIAN PROFILE
   * ---------------------------------------------------------- */

  if (
    typeof insertTechnician_ !==
    'function'
  ) {

    throw new Error(
      'Technician database module is unavailable.'
    );

  }


  insertTechnician_({

    TechnicianID:
      technicianId,

    UserID:
      userId,

    TechnicianName:
      name,

    Age:
      age,

    Mobile:
      mobile,

    Email:
      email,

    Address:
      address,

    PhotoURL:
      photoData.photoUrl,

    PhotoFileID:
      photoData.photoFileId,

    Status:
      SCD_CONFIG.TECHNICIAN.DEFAULT_STATUS,

    CreatedBy:
      admin.user.UserID,

    CreatedAt:
      now,

    UpdatedAt:
      now,

    LastLoginAt:
      ''

  });


  logAuthEvent_(
    'TECHNICIAN_CREATED',
    technicianId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Technician account created successfully.',

    data: {

      technicianId:
        technicianId,

      userId:
        userId,

      name:
        name,

      mobile:
        mobile,

      email:
        email,

      role:
        SCD_CONFIG.ROLES.TECHNICIAN,

      status:
        SCD_CONFIG.TECHNICIAN.DEFAULT_STATUS,

      photoUrl:
        photoData.photoUrl || ''

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * ADMIN LIST TECHNICIANS
 * ============================================================ */

function adminListTechnicians_(
  payload,
  requestId
) {

  requireAdminSession_(
    payload
  );


  if (
    typeof getAllTechnicians_ !==
    'function'
  ) {

    throw new Error(
      'Technician database module is unavailable.'
    );

  }


  var technicians =
    getAllTechnicians_();


  return {

    success: true,

    status: 'success',

    message:
      'Technicians loaded successfully.',

    data: {

      technicians:
        technicians || [],

      count:
        technicians
          ? technicians.length
          : 0

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * ADMIN UPDATE TECHNICIAN
 * ============================================================ */

function adminUpdateTechnician_(
  payload,
  requestId
) {

  var admin =
    requireAdminSession_(
      payload
    );


  var technicianId =
    String(
      payload.technicianId || ''
    ).trim();


  if (!technicianId) {

    return authError_(
      'Technician ID is required.'
    );

  }


  if (
    typeof findTechnicianById_ !==
    'function'
  ) {

    throw new Error(
      'Technician database module is unavailable.'
    );

  }


  var technician =
    findTechnicianById_(
      technicianId
    );


  if (!technician) {

    return authError_(
      'Technician not found.'
    );

  }


  var updates = {};


  if (
    payload.technicianName !==
    undefined ||
    payload.name !==
    undefined
  ) {

    var name =
      cleanTechnicianName_(
        payload.technicianName ||
        payload.name
      );


    if (!name) {

      return authError_(
        'Technician name is required.'
      );

    }


    updates.TechnicianName =
      name;

  }


  if (
    payload.age !==
    undefined
  ) {

    var age =
      Number(
        payload.age
      );


    if (
      !isValidTechnicianAge_(
        age
      )
    ) {

      return authError_(
        'Invalid technician age.'
      );

    }


    updates.Age =
      age;

  }


  if (
    payload.mobile !==
    undefined
  ) {

    var mobile =
      normalizeMobile_(
        payload.mobile
      );


    if (
      !isValidMobile_(
        mobile
      )
    ) {

      return authError_(
        'Invalid mobile number.'
      );

    }


    updates.Mobile =
      mobile;

  }


  if (
    payload.email !==
    undefined
  ) {

    var email =
      normalizeEmail_(
        payload.email
      );


    if (
      email &&
      !isValidEmail_(
        email
      )
    ) {

      return authError_(
        'Invalid email address.'
      );

    }


    updates.Email =
      email;

  }


  if (
    payload.address !==
    undefined
  ) {

    var address =
      cleanTechnicianAddress_(
        payload.address
      );


    if (
      address.length >
      SCD_CONFIG.TECHNICIAN.MAX_ADDRESS_LENGTH
    ) {

      return authError_(
        'Address is too long.'
      );

    }


    updates.Address =
      address;

  }


  if (
    payload.status !==
    undefined
  ) {

    var status =
      String(
        payload.status
      )
        .trim()
        .toUpperCase();


    if (
      [
        'ACTIVE',
        'INACTIVE'
      ].indexOf(
        status
      ) === -1
    ) {

      return authError_(
        'Invalid technician status.'
      );

    }


    updates.Status =
      status;

  }


  /*
   * Password reset by Admin.
   */

  if (
    payload.password
  ) {

    var newPassword =
      String(
        payload.password
      );


    if (
      !isValidPassword_(
        newPassword
      )
    ) {

      return authError_(
        'Password must be at least 8 characters.'
      );

    }


    var salt =
      generatePasswordSalt_();


    var hash =
      hashPassword_(
        newPassword,
        salt
      );


    if (
      technician.UserID
    ) {

      var user =
        findUserById_(
          technician.UserID
        );


      if (user) {

        updateUserPassword_(
          user,
          hash,
          salt
        );

      }

    }

  }


  /*
   * Update profile.
   */

  if (
    typeof updateTechnician_ !==
    'function'
  ) {

    throw new Error(
      'Technician database module is unavailable.'
    );

  }


  updates.UpdatedAt =
    getServerDateTime_();


  updates.UpdatedBy =
    admin.user.UserID;


  updateTechnician_(
    technicianId,
    updates
  );


  logAuthEvent_(
    'TECHNICIAN_UPDATED',
    technicianId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Technician updated successfully.',

    data: {

      technicianId:
        technicianId

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * ADMIN DELETE TECHNICIAN
 * ============================================================ */

function adminDeleteTechnician_(
  payload,
  requestId
) {

  var admin =
    requireAdminSession_(
      payload
    );


  var technicianId =
    String(
      payload.technicianId || ''
    ).trim();


  if (!technicianId) {

    return authError_(
      'Technician ID is required.'
    );

  }


  if (
    typeof findTechnicianById_ !==
    'function'
  ) {

    throw new Error(
      'Technician database module is unavailable.'
    );

  }


  var technician =
    findTechnicianById_(
      technicianId
    );


  if (!technician) {

    return authError_(
      'Technician not found.'
    );

  }


  /*
   * Soft delete is safer than permanently deleting
   * operational records.
   */

  if (
    typeof updateTechnician_ ===
    'function'
  ) {

    updateTechnician_(
      technicianId,
      {

        Status:
          'DELETED',

        UpdatedAt:
          getServerDateTime_(),

        UpdatedBy:
          admin.user.UserID

      }
    );

  }


  /*
   * Also disable login.
   */

  if (
    technician.UserID
  ) {

    var user =
      findUserById_(
        technician.UserID
      );


    if (
      user &&
      typeof updateUserStatus_ ===
      'function'
    ) {

      updateUserStatus_(
        user,
        'INACTIVE'
      );

    }

  }


  logAuthEvent_(
    'TECHNICIAN_DELETED',
    technicianId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Technician account deactivated successfully.',

    requestId:
      requestId

  };

}


/* ============================================================
 * ADMIN TOGGLE TECHNICIAN
 * ============================================================ */

function adminToggleTechnician_(
  payload,
  requestId
) {

  var admin =
    requireAdminSession_(
      payload
    );


  var technicianId =
    String(
      payload.technicianId || ''
    ).trim();


  var requestedStatus =
    String(
      payload.status || ''
    )
      .trim()
      .toUpperCase();


  if (!technicianId) {

    return authError_(
      'Technician ID is required.'
    );

  }


  if (
    [
      'ACTIVE',
      'INACTIVE'
    ].indexOf(
      requestedStatus
    ) === -1
  ) {

    return authError_(
      'Status must be ACTIVE or INACTIVE.'
    );

  }


  var technician =
    findTechnicianById_(
      technicianId
    );


  if (!technician) {

    return authError_(
      'Technician not found.'
    );

  }


  updateTechnician_(
    technicianId,
    {

      Status:
        requestedStatus,

      UpdatedAt:
        getServerDateTime_(),

      UpdatedBy:
        admin.user.UserID

    }
  );


  if (
    technician.UserID
  ) {

    var user =
      findUserById_(
        technician.UserID
      );


    if (
      user &&
      typeof updateUserStatus_ ===
      'function'
    ) {

      updateUserStatus_(
        user,
        requestedStatus
      );

    }

  }


  logAuthEvent_(
    'TECHNICIAN_STATUS_CHANGED',
    technicianId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Technician status updated successfully.',

    data: {

      technicianId:
        technicianId,

      status:
        requestedStatus

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * ADMIN RESET TECHNICIAN PASSWORD
 * ============================================================ */

function adminResetTechnicianPassword_(
  payload,
  requestId
) {

  var admin =
    requireAdminSession_(
      payload
    );


  var technicianId =
    String(
      payload.technicianId || ''
    ).trim();


  var newPassword =
    String(
      payload.password || ''
    );


  if (!technicianId) {

    return authError_(
      'Technician ID is required.'
    );

  }


  if (
    !isValidPassword_(
      newPassword
    )
  ) {

    return authError_(
      'Password must be at least 8 characters.'
    );

  }


  var technician =
    findTechnicianById_(
      technicianId
    );


  if (!technician) {

    return authError_(
      'Technician not found.'
    );

  }


  if (
    !technician.UserID
  ) {

    return authError_(
      'Technician login account is missing.'
    );

  }


  var user =
    findUserById_(
      technician.UserID
    );


  if (!user) {

    return authError_(
      'Technician user account was not found.'
    );

  }


  var salt =
    generatePasswordSalt_();


  var hash =
    hashPassword_(
      newPassword,
      salt
    );


  updateUserPassword_(
    user,
    hash,
    salt
  );


  /*
   * Invalidate old technician sessions.
   */

  if (
    typeof invalidateUserSessions_ ===
    'function'
  ) {

    invalidateUserSessions_(
      user.UserID
    );

  }


  logAuthEvent_(
    'TECHNICIAN_PASSWORD_RESET_BY_ADMIN',
    technicianId,
    requestId
  );


  return {

    success: true,

    status: 'success',

    message:
      'Technician password reset successfully.',

    data: {

      technicianId:
        technicianId

    },

    requestId:
      requestId

  };

}


/* ============================================================
 * TECHNICIAN PHOTO UPLOAD
 * ============================================================ */

function uploadTechnicianPhoto_(
  data
) {

  if (
    !data
  ) {

    throw new Error(
      'Photo data is missing.'
    );

  }


  var base64 =
    String(
      data.photoBase64 || ''
    );


  var mimeType =
    String(
      data.photoMimeType || ''
    )
      .trim()
      .toLowerCase();


  if (!base64) {

    return {

      photoUrl:
        '',

      photoFileId:
        ''

    };

  }


  if (
    !isAllowedTechnicianPhotoType_(
      mimeType
    )
  ) {

    throw new Error(
      'Unsupported technician photo format.'
    );

  }


  var estimatedBytes =
    Math.floor(
      (
        base64.length *
        3
      ) / 4
    );


  if (
    !isAllowedTechnicianPhotoSize_(
      estimatedBytes
    )
  ) {

    throw new Error(
      'Technician photo is too large.'
    );

  }


  /*
   * Remove possible data URL prefix.
   */

  base64 =
    base64.replace(
      /^data:[^;]+;base64,/i,
      ''
    );


  var bytes =
    Utilities.base64Decode(
      base64
    );


  var extension =
    getPhotoExtension_(
      mimeType
    );


  var technicianId =
    String(
      data.technicianId || 'TECH'
    );


  var fileName =
    'TECHNICIAN_' +
    technicianId +
    '_' +
    new Date()
      .getTime() +
    extension;


  /*
   * Create / reuse Drive folder.
   */

  var folders =
    DriveApp.getFoldersByName(
      SCD_CONFIG
        .PHOTO_UPLOAD
        .DRIVE_FOLDER_NAME
    );


  var folder;


  if (
    folders.hasNext()
  ) {

    folder =
      folders.next();

  } else {

    folder =
      DriveApp.createFolder(
        SCD_CONFIG
          .PHOTO_UPLOAD
          .DRIVE_FOLDER_NAME
      );

  }


  var blob =
    Utilities.newBlob(
      bytes,
      mimeType,
      fileName
    );


  var file =
    folder.createFile(
      blob
    );


  /*
   * File access.
   *
   * The URL is stored as a reference.
   */

  try {

    file.setSharing(
      DriveApp.Access.ANYONE_WITH_LINK,
      DriveApp.Permission.VIEW
    );

  } catch (sharingError) {

    /*
     * Continue if domain/admin policy blocks
     * public link sharing.
     */

    console.log(
      'Technician photo sharing policy:',
      sharingError.message
    );

  }


  return {

    photoUrl:
      file.getUrl(),

    photoFileId:
      file.getId()

  };

}


/* ============================================================
 * PHOTO EXTENSION
 * ============================================================ */

function getPhotoExtension_(
  mimeType
) {

  switch (
    String(
      mimeType || ''
    ).toLowerCase()
  ) {

    case 'image/jpeg':
      return '.jpg';

    case 'image/jpg':
      return '.jpg';

    case 'image/png':
      return '.png';

    case 'image/webp':
      return '.webp';

    default:
      return '.jpg';

  }

}


/* ============================================================
 * TECHNICIAN NAME
 * ============================================================ */

function cleanTechnicianName_(
  value
) {

  var name =
    String(
      value || ''
    )
      .replace(
        /\s+/g,
        ' '
      )
      .trim();


  if (
    name.length >
    SCD_CONFIG.TECHNICIAN.MAX_NAME_LENGTH
  ) {

    name =
      name.substring(
        0,
        SCD_CONFIG.TECHNICIAN.MAX_NAME_LENGTH
      );

  }


  return name;

}


/* ============================================================
 * TECHNICIAN ADDRESS
 * ============================================================ */

function cleanTechnicianAddress_(
  value
) {

  var address =
    String(
      value || ''
    )
      .replace(
        /\s+/g,
        ' '
      )
      .trim();


  if (
    address.length >
    SCD_CONFIG.TECHNICIAN.MAX_ADDRESS_LENGTH
  ) {

    address =
      address.substring(
        0,
        SCD_CONFIG.TECHNICIAN.MAX_ADDRESS_LENGTH
      );

  }


  return address;

}


/* ============================================================
 * TECHNICIAN AGE
 * ============================================================ */

function isValidTechnicianAge_(
  age
) {

  var value =
    Number(
      age
    );


  return (
    isFinite(value) &&
    Math.floor(value) === value &&
    value >= 18 &&
    value <= 120
  );

}


/* ============================================================
 * PHOTO NAME
 * ============================================================ */

function cleanPhotoName_(
  value
) {

  var name =
    String(
      value || ''
    )
      .trim()
      .replace(
        /[^a-zA-Z0-9._-]/g,
        '_'
      );


  if (
    name.length >
    100
  ) {

    name =
      name.substring(
        0,
        100
      );

  }


  return name;

}