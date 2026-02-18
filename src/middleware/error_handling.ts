import type { Response } from "express";

export const errorHandler = (err: any, res: Response) => {
  return res.status(500).send({ message: err.message });
};