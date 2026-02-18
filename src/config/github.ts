import passport from "passport";
import { Strategy as GitHubStrategy, Profile } from "passport-github2";

passport.use(
  "github",   // ⭐ NAME MUST MATCH ROUTE
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      callbackURL: "http://localhost:1928/auth/github/callback",
      scope: ["user:email"],
    },
    async (
      _accessToken: string,
      _refreshToken: string,
      profile: Profile,
      done: Function
    ) => {
      console.log("GitHub Profile:", profile.username); // DEBUG
      done(null, profile);
    }
  )
);
