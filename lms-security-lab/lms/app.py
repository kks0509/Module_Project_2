from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    abort
)
import pymysql
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = "lms-development-secret-key"

SQLI_LOGIN_ENABLED = (
    os.getenv("LAB_SQLI_LOGIN", "false").lower() == "true"
)

SQLI_STUDENT_SEARCH_ENABLED = (
    os.getenv("LAB_SQLI_STUDENT_SEARCH", "false").lower() == "true"
)

BAC_ADMIN_ENABLED = (
    os.getenv("LAB_BAC_ADMIN", "false").lower() == "true"
)

def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "db"),
        user=os.getenv("DB_USER", "lms_user"),
        password=os.getenv("DB_PASSWORD", "lmspass"),
        database=os.getenv("DB_NAME", "lms"),
    charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )


def student_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("index"))

        if session.get("role") != "student":
            return "접근 권한이 없습니다.", 403

        return func(*args, **kwargs)

    return wrapper


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        # 로그인하지 않은 사용자는 차단
        if "user_id" not in session:
            return redirect(url_for("login"))

        # 취약 모드가 아닐 때만 관리자 권한 검사
        if not BAC_ADMIN_ENABLED:
            if session.get("role") != "admin":
                abort(403)

        # 취약 모드에서는 로그인 여부만 확인
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")

def index():

    if "user_id" in session:

        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("student_main"))

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            if SQLI_LOGIN_ENABLED:
                # 취약 코드
                sql = (
                    f"SELECT id, username, role "
                    f"FROM users "
                    f"WHERE username = '{username}' AND password = '{password}'"
                )

                print("[SQLI LAB QUERY]", sql)
                cursor.execute(sql)

            else:
                # 안전한 코드
                sql = """
                    SELECT id, username, role
                    FROM users
                    WHERE username = %s
                    AND password = %s
                """

                cursor.execute(
                    sql,
                    (username, password)
                )

            user = cursor.fetchone()

    finally:
        conn.close()

    if not user:
        return render_template(
            "login.html",
            error="아이디 또는 비밀번호가 올바르지 않습니다."
        )

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    if user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("student_main"))


@app.route("/student")
@student_required
def student_main():

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT id, student_no, name, department
                FROM students
                WHERE user_id = %s
                """,
                (session["user_id"],)
            )

            student = cursor.fetchone()

            cursor.execute(
                """
                SELECT COUNT(*) AS course_count
                FROM enrollments
                WHERE student_id = %s
                """,
                (student["id"],)
            )

            course_count = cursor.fetchone()["course_count"]

            cursor.execute(
                """
                SELECT title, created_at
                FROM notices
                ORDER BY created_at DESC
                LIMIT 3
                """
            )

            notices = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "student_main.html",
        student=student,
        course_count=course_count,
        notices=notices
    )


@app.route("/student/profile")
@student_required
def student_profile():
    target_student_id = request.args.get("student_id")
    if not target_student_id:
        return redirect(url_for("student_profile", student_id=session["user_id"]))

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    student_no,
                    name,
                    department,
                    email,
                    phone
                FROM students
                WHERE user_id = %s
                """,
                (target_student_id,)
            )

            student = cursor.fetchone()

    finally:
        conn.close()

    return render_template(
        "profile.html",
        student=student
    )


@app.route("/student/grades")
@student_required
def student_grades():
    target_student_id = request.args.get("student_id")
    if not target_student_id:
        return redirect(url_for("student_grades", student_id=session["user_id"]))

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    c.course_code,
                    c.course_name,
                    c.professor,
                    g.score,
                    g.letter_grade
                FROM students s
                JOIN enrollments e
                    ON s.id = e.student_id
                JOIN courses c
                    ON e.course_id = c.id
                LEFT JOIN grades g
                    ON e.id = g.enrollment_id
                WHERE s.user_id = %s
                ORDER BY c.course_code
                """,
                (target_student_id,)
            )

            grades = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "grades.html",
        grades=grades
    )


@app.route("/student/courses")
@student_required
def student_courses():

    keyword = request.args.get("keyword", "").strip()

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            if keyword:

                cursor.execute(
                    """
                    SELECT
                        course_code,
                        course_name,
                        professor
                    FROM courses
                    WHERE course_name LIKE %s
                    OR professor LIKE %s
                    OR course_code LIKE %s
                    ORDER BY course_code
                    """,
                    (
                        f"%{keyword}%",
                        f"%{keyword}%",
                        f"%{keyword}%"
                    )
                )

            else:

                cursor.execute(
                    """
                    SELECT
                        course_code,
                        course_name,
                        professor
                    FROM courses
                    ORDER BY course_code
                    """
                )

            courses = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "courses.html",
        courses=courses,
        keyword=keyword
    )


@app.route("/student/notices")
@student_required
def student_notices():

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    title,
                    content,
                    created_at
                FROM notices
                ORDER BY created_at DESC
                """
            )

            notices = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "notices.html",
        notices=notices
    )


@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute("SELECT COUNT(*) AS count FROM students")
            student_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM courses")
            course_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM enrollments")
            enrollment_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) AS count FROM notices")
            notice_count = cursor.fetchone()["count"]

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        student_count=student_count,
        course_count=course_count,
        enrollment_count=enrollment_count,
        notice_count=notice_count
    )


@app.route("/admin/students")
@admin_required
def admin_students():
    keyword = request.args.get("keyword", "").strip()

    students = []

    # 검색어가 입력된 경우에만 DB 조회
    if keyword:
        conn = get_db()

        try:
            with conn.cursor() as cursor:

                # SQL Injection 실습 모드
                if SQLI_STUDENT_SEARCH_ENABLED:
                    sql = f"""
                        SELECT
                            id,
                            student_no,
                            name,
                            department,
                            email
                        FROM students
                        WHERE student_no LIKE '%{keyword}%'
                           OR name LIKE '%{keyword}%'
                           OR department LIKE '%{keyword}%'
                        ORDER BY student_no
                    """

                    print(
                        "[SQLI STUDENT SEARCH QUERY]",
                        sql,
                        flush=True
                    )

                    cursor.execute(sql)

                # 정상 모드
                else:
                    sql = """
                        SELECT
                            id,
                            student_no,
                            name,
                            department,
                            email
                        FROM students
                        WHERE student_no LIKE %s
                           OR name LIKE %s
                           OR department LIKE %s
                        ORDER BY student_no
                    """

                    search_value = f"%{keyword}%"

                    cursor.execute(
                        sql,
                        (
                            search_value,
                            search_value,
                            search_value
                        )
                    )

                students = cursor.fetchall()

        finally:
            conn.close()

    return render_template(
        "admin_students.html",
        students=students,
        keyword=keyword
    )


@app.route("/admin/students/<int:student_id>")
@admin_required
def admin_student_detail(student_id):

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    student_no,
                    name,
                    department,
                    email,
                    phone
                FROM students
                WHERE id = %s
                """,
                (student_id,)
            )

            student = cursor.fetchone()

            if not student:
                return "학생을 찾을 수 없습니다.", 404

            cursor.execute(
                """
                SELECT
                    c.course_code,
                    c.course_name,
                    c.professor,
                    g.score,
                    g.letter_grade
                FROM enrollments e
                JOIN courses c
                    ON e.course_id = c.id
                LEFT JOIN grades g
                    ON e.id = g.enrollment_id
                WHERE e.student_id = %s
                ORDER BY c.course_code
                """,
                (student_id,)
            )

            grades = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "admin_student_detail.html",
        student=student,
        grades=grades
    )


@app.route("/admin/grades", methods=["GET", "POST"])
@admin_required
def admin_grades():

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            if request.method == "POST":

                enrollment_id = request.form.get("enrollment_id")
                score = request.form.get("score")
                letter_grade = request.form.get("letter_grade")

                cursor.execute(
                    """
                    UPDATE grades
                    SET score = %s,
                        letter_grade = %s
                    WHERE enrollment_id = %s
                    """,
                    (
                        score,
                        letter_grade,
                        enrollment_id
                    )
                )

                conn.commit()

                return redirect(url_for("admin_grades"))

            cursor.execute(
                """
                SELECT
                    e.id AS enrollment_id,
                    s.student_no,
                    s.name,
                    c.course_code,
                    c.course_name,
                    g.score,
                    g.letter_grade
                FROM enrollments e
                JOIN students s
                    ON e.student_id = s.id
                JOIN courses c
                    ON e.course_id = c.id
                LEFT JOIN grades g
                    ON e.id = g.enrollment_id
                ORDER BY s.student_no, c.course_code
                """
            )

            grades = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "admin_grades.html",
        grades=grades
    )


@app.route("/admin/courses", methods=["GET", "POST"])
@admin_required
def admin_courses():

    conn = get_db()

    try:
        with conn.cursor() as cursor:

            error = None

            if request.method == "POST":

                course_code = request.form.get("course_code", "").strip()
                course_name = request.form.get("course_name", "").strip()
                professor = request.form.get("professor", "").strip()

                try:
                    cursor.execute(
                        """
                        INSERT INTO courses
                        (course_code, course_name, professor)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            course_code,
                            course_name,
                            professor
                        )
                    )

                    conn.commit()

                except pymysql.err.IntegrityError:
                    conn.rollback()
                    error = "이미 존재하는 과목 코드입니다."

            cursor.execute(
                """
                SELECT
                    id,
                    course_code,
                    course_name,
                    professor
                FROM courses
                ORDER BY course_code
                """
            )

            courses = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        "admin_courses.html",
        courses=courses,
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("index"))


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
