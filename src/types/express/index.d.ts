import "express";

declare global {
  namespace Express {
    interface UserPayload {
      _id: string;
      role?: string;
    }

    interface Request {
      user?: UserPayload;
    }
  }
}