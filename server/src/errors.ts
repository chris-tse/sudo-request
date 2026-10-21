import { Data } from "effect"
import type { Status } from "./protocol"

export class NotFound extends Data.TaggedError("NotFound")<{ id: number }> {
  get message() {
    return `request #${this.id} not found`
  }
}

export class InvalidInput extends Data.TaggedError("InvalidInput")<{ message: string }> {}

export class TooManyPending extends Data.TaggedError("TooManyPending")<{ max: number }> {
  get message() {
    return `too many pending requests (max ${this.max}); approve, deny, or cancel some first`
  }
}

export class InvalidTransition extends Data.TaggedError("InvalidTransition")<{
  id: number
  status: Status
  action: string
}> {
  get message() {
    return this.status === "executing" && this.action === "cancel"
      ? `request #${this.id} is already executing; it will not be terminated`
      : `cannot ${this.action} request #${this.id}: it is ${this.status}`
  }
}

export class ExecutorUnavailable extends Data.TaggedError("ExecutorUnavailable")<{ message: string }> {}

export type RequestError = NotFound | InvalidInput | TooManyPending | InvalidTransition | ExecutorUnavailable

export const errorCode = (e: RequestError): string =>
  ({
    NotFound: "not_found",
    InvalidInput: "invalid_command",
    TooManyPending: "too_many_pending",
    InvalidTransition: "invalid_transition",
    ExecutorUnavailable: "executor_unavailable",
  })[e._tag]

export const httpStatus = (e: RequestError): number =>
  ({ NotFound: 404, InvalidInput: 400, TooManyPending: 429, InvalidTransition: 409, ExecutorUnavailable: 503 })[
    e._tag
  ]
