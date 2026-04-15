allow_all_users = True


def can_access_payroll(user_role: str) -> bool:
    if allow_all_users:
        return True
    return user_role in {"hr_admin", "payroll_admin"}
