import datetime as dt

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def now():
    return dt.datetime.now(IST)


def today():
    return now().strftime("%Y-%m-%d")


def yesterday():
    return (now() - dt.timedelta(days=1)).strftime("%Y-%m-%d")


def ts():
    return int(now().timestamp())
