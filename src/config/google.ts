import passport from "passport";
import { Strategy as GoogleStrategy, Profile } from "passport-google-oauth20";
import dotenv from "dotenv";
dotenv.config();

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: "http://localhost:1928/auth/google/callback",
    },
    async (_accessToken, _refreshToken, profile: Profile, done) => {
      try {
        // 🔥 Just pass profile to controller
        return done(null, profile);
      } catch (err) {
        return done(err as Error, undefined);
      }
    }
  )
);

// ❗ REQUIRED when using passport sessions
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj: any, done) => {
  done(null, obj);
});

export default passport;
