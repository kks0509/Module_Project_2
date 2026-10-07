CREATE DATABASE IF NOT EXISTS lms
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE lms;

SET NAMES utf8mb4;

-- 사용자
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    role ENUM('student', 'admin') NOT NULL
);

-- 학생 정보
CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    student_no VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(50) NOT NULL,
    department VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    phone VARCHAR(30),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 강의
CREATE TABLE courses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    course_code VARCHAR(20) NOT NULL UNIQUE,
    course_name VARCHAR(100) NOT NULL,
    professor VARCHAR(50) NOT NULL
);

-- 수강 정보
CREATE TABLE enrollments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    course_id INT NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students(id),
    FOREIGN KEY (course_id) REFERENCES courses(id)
);

-- 성적
CREATE TABLE grades (
    id INT AUTO_INCREMENT PRIMARY KEY,
    enrollment_id INT NOT NULL UNIQUE,
    score DECIMAL(5,2),
    letter_grade VARCHAR(5),
    FOREIGN KEY (enrollment_id) REFERENCES enrollments(id)
);

-- 공지사항
CREATE TABLE notices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 사용자 데이터
INSERT INTO users (username, password, role) VALUES
('admin', 'admin123', 'admin'),
('student01', 'student123', 'student'),
('student02', 'student123', 'student');


-- 학생 데이터
INSERT INTO students
(user_id, student_no, name, department, email, phone)
VALUES
(
    (SELECT id FROM users WHERE username = 'student01'),
    '20260001',
    '김학생',
    '컴퓨터공학과',
    'student01@test.local',
    '010-0000-0001'
),
(
    (SELECT id FROM users WHERE username = 'student02'),
    '20260002',
    '이학생',
    '정보보호학과',
    'student02@test.local',
    '010-0000-0002'
);


-- 강의 데이터
INSERT INTO courses
(course_code, course_name, professor)
VALUES
('CSE101', '컴퓨터네트워크', '김교수'),
('SEC201', '정보보안', '이교수'),
('WEB301', '웹보안', '박교수'),
('DB202', '데이터베이스', '최교수');


-- 수강 데이터
INSERT INTO enrollments
(student_id, course_id)
VALUES
(1, 1),
(1, 2),
(1, 3),

(2, 2),
(2, 3),
(2, 4);


-- 성적 데이터
INSERT INTO grades
(enrollment_id, score, letter_grade)
VALUES
(1, 95, 'A+'),
(2, 91, 'A'),
(3, 88, 'B+'),
(4, 92, 'A'),
(5, 85, 'B+'),
(6, 89, 'B+');


-- 공지사항
INSERT INTO notices
(title, content)
VALUES
('중간고사 일정 안내',
 '중간고사 일정은 각 강의별 공지를 확인해 주세요.'),

('LMS 점검 안내',
 '이번 주 금요일 오후 LMS 서버 점검이 예정되어 있습니다.'),

('과제 제출 안내',
 '과제 제출 마감 시간을 반드시 확인해 주세요.');
