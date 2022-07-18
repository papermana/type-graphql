import { MiddlewareFn } from "../interfaces/Middleware";
import { AuthChecker, AuthCheckerFn, AuthCheckerReturnType, AuthMode } from "../interfaces";
import { UnauthorizedError, ForbiddenError } from "../errors";
import { IOCContainer } from "../utils/container";
import { AuthCheckerUseErrorMode, AuthCheckerUseNullMode } from "../utils/symbols";

export function AuthMiddleware(
  authChecker: AuthChecker<any, any>,
  container: IOCContainer,
  authMode: AuthMode,
  roles: any[],
): MiddlewareFn {
  return async (action, next) => {
    let accessGranted: AuthCheckerReturnType;
    if (authChecker.prototype) {
      const authCheckerInstance = await container.getInstance(authChecker, action);
      accessGranted = await authCheckerInstance.check(action, roles);
    } else {
      accessGranted = await (authChecker as AuthCheckerFn<any, any>)(action, roles);
    }

    const throwError = () => {
      throw roles.length === 0 ? new UnauthorizedError() : new ForbiddenError();
    };

    if (accessGranted === AuthCheckerUseErrorMode) {
      return throwError();
    }

    if (accessGranted === AuthCheckerUseNullMode) {
      return null;
    }

    if (!accessGranted) {
      if (authMode === "null") {
        return null;
      } else if (authMode === "error") {
        return throwError();
      }
    }

    return next();
  };
}
