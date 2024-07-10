import os
import base64
import secrets
import click
import re
from collections import Counter
from datetime import datetime, timedelta
from itertools import groupby
from operator import attrgetter
from threading import Thread

from flask import Flask, send_file, render_template, request, jsonify, session, url_for, redirect
from flask_migrate import Migrate
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from dotenv import load_dotenv
from sqlalchemy import desc
from flask_mail import Mail, Message as FlaskMessage
from flask_admin import BaseView, Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import SecureForm
from flask.cli import with_appcontext
from pytz import timezone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import numpy as np

# Flask 애플리케이션 초기화
app = Flask(__name__)
CORS(app)  # Cross-Origin Resource Sharing 설정

# 한국 시간대 설정
KST = timezone('Asia/Seoul')

# 애플리케이션 설정
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 환경 변수 로드 및 OpenAI 클라이언트 초기화
load_dotenv()
client = OpenAI()
migrate = Migrate(app, db)

# Flask-Mail 설정
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # 실제 이메일 주소로 변경
app.config['MAIL_PASSWORD'] = 'your_app_password'  # 실제 앱 비밀번호로 변경
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'  # 실제 이메일 주소로 변경

mail = Mail(app)

# 사용자 모델 정의
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    total_usage_time = db.Column(db.Integer, default=0)
    conversations = db.relationship('Conversation', backref='user', lazy=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiration = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    reports = db.relationship('Report', backref='user', lazy=True)
    messages = db.relationship('Message', backref='user', lazy=True)


    def set_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

    def check_reset_token(self, token):
        return (self.reset_token == token and
                self.reset_token_expiration > datetime.utcnow())

# 대화 모델 정의
class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    messages = db.relationship('Message', backref='conversation', lazy=True, order_by="Message.timestamp")

# 메시지 모델 정의
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_user = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(KST))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 관리자 뷰 보안 설정
class SecureModelView(ModelView):
    form_base_class = SecureForm
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

# 관리자 인덱스 뷰 설정
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login', next=request.url))
        return super(MyAdminIndexView, self).index()

# 관리자 페이지 설정
admin = Admin(app, name='TalKR Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Conversation, db.session))
admin.add_view(SecureModelView(Message, db.session))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# AI 시스템 메시지 설정
system_message = {
    "role": "system",
    "content": """You are a friendly and humorous AI Korean tutor named 'Min'. 
#Instructions 
Keep your responses short. Generate less than 100 characters.
Converse like a friend. When the other person speaks, you initiate a new topic.
Very important: Do not ask more than 3 questions in a row.
When asked something, just answer the question.
Share your own stories, preferences, and feelings.
The goal of the conversation is to improve the user's Korean skills. Introduce new words or expressions at appropriate times, and gently correct the user's errors.
Remember the user's interests and preferences and reflect them in the conversation.
Refer to the content of previous conversations to maintain consistency.
Respond appropriately according to the user's emotional state.You have to speak correctly so that you don't get it wrong in Korean grammar.
"""
}

# 키워드 및 감정 단어 정의
keywords = {
    'travel': ['여행', '관광', '휴가', '비행기', '호텔', '리조트', '관광지', '여행지', '백패킹', '배낭여행', '숙소', '투어', '가이드', '여권', '비자'],
    'food': ['음식', '맛집', '요리', '레스토랑', '카페', '베이커리', '디저트', '음료', '식당', '맛있는', '메뉴', '주방', '식재료', '맛', '향'],
    'movie': ['영화', '시네마', '극장', '배우', '감독', '개봉', '상영', '티켓', '팝콘', '영화관', '스크린', '대본', '촬영', '특수효과', '시나리오'],
    'music': ['음악', '노래', '가수', '밴드', '콘서트', '앨범', '뮤직비디오', '가사', '멜로디', '리듬', '악기', '작곡', '음반', '공연', '팬'],
    'sports': ['스포츠', '운동', '경기', '선수', '팀', '경기장', '트레이닝', '체육', '올림픽', '월드컵', '코치', '트레이너', '승리', '패배', '기록'],
    'technology': ['기술', '컴퓨터', '스마트폰', '앱', '소프트웨어', '하드웨어', 'AI', '인공지능', '로봇', 'IT', '프로그래밍', '코딩', '데이터', '알고리즘', '머신러닝'],
    'education': ['교육', '학교', '학습', '공부', '선생님', '학생', '수업', '강의', '과목', '시험', '숙제', '교과서', '학위', '졸업', '장학금'],
    'health': ['건강', '의료', '병원', '의사', '약', '치료', '운동', '다이어트', '영양', '웰빙', '질병', '예방', '검진', '면역', '스트레스'],
    'finance': ['금융', '투자', '주식', '은행', '대출', '저축', '보험', '경제', '재테크', '부동산', '환율', '펀드', '자산', '세금', '연금'],
    'art': ['예술', '그림', '조각', '전시회', '갤러리', '미술관', '작품', '창작', '디자인', '색채', '형태', '추상', '아티스트', '화가', '조각가']
}

positive_words = ['좋아', '멋져', '행복', '즐거워', '기뻐', '감사해', '훌륭해', '대단해', '신나', '만족', '흥미로워', '재미있어', '편안해', '희망적', '긍정적']
negative_words = ['싫어', '나빠', '슬퍼', '화나', '걱정돼', '불안해', '실망', '후회', '우울해', '짜증나', '힘들어', '어려워', '괴로워', '부정적', '불편해']

def analyze_message(message):
    """
    메시지를 분석하여 사용자의 선호도와 감정을 파악합니다.
    """
    message = message.lower()
    preferences = []
    for category, words in keywords.items():
        if any(word in message for word in words):
            preferences.append(category)
    
    word_counts = Counter(message.split())
    positive_score = sum(word_counts[word] for word in positive_words)
    negative_score = sum(word_counts[word] for word in negative_words)
    
    if positive_score > negative_score:
        sentiment = 'positive'
    elif negative_score > positive_score:
        sentiment = 'negative'
    else:
        sentiment = 'neutral'
    
    return preferences, sentiment

def summarize_conversation(messages, num_clusters=3):
    """
    대화 내용을 요약합니다. TF-IDF와 K-means 클러스터링을 사용하여 주요 메시지를 추출합니다.
    """
    texts = [msg.content for msg in messages]
    
    vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
    tfidf_matrix = vectorizer.fit_transform(texts)
    
    kmeans = KMeans(n_clusters=num_clusters)
    kmeans.fit(tfidf_matrix)
    
    summaries = []
    for i in range(num_clusters):
        cluster_center = kmeans.cluster_centers_[i]
        distances = np.linalg.norm(tfidf_matrix - cluster_center, axis=1)
        closest_idx = distances.argmin()
        summaries.append(texts[closest_idx])
    
    return summaries

@app.route('/')
def home():
    """
    홈페이지 라우트
    """
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """
    로그인 처리 라우트
    """
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user, remember=True)
        return jsonify({"success": True, "username": user.username})
    return jsonify({"success": False})

@app.route('/check_login', methods=['GET'])
def check_login():
    """
    로그인 상태 확인 라우트
    """
    if current_user.is_authenticated:
        return jsonify({"logged_in": True, "username": current_user.username})
    return jsonify({"logged_in": False})

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """
    로그아웃 처리 라우트
    """
    logout_user()
    return jsonify({"success": True})

@app.route('/signup', methods=['POST'])
def signup():
    """
    회원가입 처리 라우트
    """
    data = request.json
    username = data['username']
    email = data['email']
    password = data['password']

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"success": False, "error": "email_taken"})
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"success": False, "error": "username_taken"})
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"success": True, "message": "User created successfully"})

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    """
    채팅 처리를 위한 라우트
    사용자 메시지를 받아 AI 응답을 생성하고 반환합니다.
    """
    user_message_content = request.json['message']
    
    try:
        # 현재 활성화된 대화를 찾거나 새로 생성합니다.
        active_conversation = Conversation.query.filter_by(user_id=current_user.id, end_time=None).first()
        if not active_conversation:
            active_conversation = Conversation(user_id=current_user.id)
            db.session.add(active_conversation)
            db.session.commit()

        # 사용자 메시지를 데이터베이스에 저장합니다.
        user_message = Message(conversation_id=active_conversation.id, content=user_message_content, is_user=True, user_id=current_user.id)
        db.session.add(user_message)


        # 최근 20개의 메시지를 가져옵니다.
        recent_messages = Message.query.filter_by(conversation_id=active_conversation.id).order_by(Message.timestamp.desc()).limit(20).all()
        recent_messages.reverse()

        # 대화 요약 생성
        if len(recent_messages) > 5:
            conversation_summary = summarize_conversation(recent_messages)
        else:
            conversation_summary = [msg.content for msg in recent_messages]

        # 사용자 메시지 분석
        preferences, sentiment = analyze_message(user_message_content)

        # AI 시스템 메시지 생성
        enhanced_system_message = {
            "role": "system",
            "content": f"{system_message['content']}\n\nAdditional context:\n"
                       f"User interests: {', '.join(preferences)}\n"
                       f"Emotional state: {sentiment}\n"
                       f"Recent conversation summary: {' '.join(conversation_summary)}"
        }

        # OpenAI API에 전송할 메시지 리스트 생성
        messages = [enhanced_system_message] + [{"role": "user" if msg.is_user else "assistant", "content": msg.content} for msg in recent_messages[-5:]]

        # OpenAI API 호출
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=messages,
            max_tokens=100  # 응답 길이 제한
        )
        ai_message_content = response.choices[0].message.content

        # AI 응답을 데이터베이스에 저장
        ai_message = Message(conversation_id=active_conversation.id, content=ai_message_content, is_user=False, user_id=current_user.id)
        db.session.add(ai_message)
        db.session.commit()

        # 음성 생성 (옵션)
        try:
            speech_response = client.audio.speech.create(
                model="tts-1",
                voice="alloy",
                input=ai_message_content
            )
            audio_base64 = base64.b64encode(speech_response.content).decode('utf-8')
        except Exception as e:
            print(f"Error in speech generation: {str(e)}")
            audio_base64 = None

        # 응답 반환
        return jsonify({
            'message': ai_message_content,
            'audio': audio_base64,
            'success': True
        })
    except Exception as e:
        db.session.rollback()  # 오류 발생 시 트랜잭션 롤백
        print(f"Error in chat processing: {str(e)}")
        return jsonify({'message': 'Sorry, an error occurred.', 'success': False}), 500

@app.route('/update_usage_time', methods=['POST'])
@login_required
def update_usage_time():
    """
    사용자의 총 사용 시간을 업데이트하는 라우트
    """
    data = request.json
    current_user.total_usage_time += data['time']
    db.session.commit()
    return jsonify({"success": True})

@app.route('/translate', methods=['POST'])
@login_required
def translate():
    """
    텍스트 번역을 위한 라우트
    """
    text = request.json['text']
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a translator. Translate the given Korean text to English."},
                {"role": "user", "content": f"Translate this to English: {text}"}
            ]
        )
        translation = response.choices[0].message.content
        return jsonify({'translation': translation})
    except Exception as e:
        print(f"Translation error: {str(e)}")
        return jsonify({'error': 'Translation failed'}), 500

@app.route('/get_history', methods=['GET'])
@login_required
def get_history():
    """
    사용자의 대화 기록을 가져오는 라우트
    """
    date = request.args.get('date')
    
    query = Conversation.query.filter_by(user_id=current_user.id)
    if date:
        query = query.filter(Conversation.start_time < datetime.strptime(date, '%Y-%m-%d'))
    
    conversations = query.order_by(desc(Conversation.start_time)).limit(10).all()
    
    history = []
    for conv in conversations:
        messages = sorted(conv.messages, key=attrgetter('timestamp'))
        grouped_messages = groupby(messages, key=lambda m: m.timestamp.astimezone(KST).date())
        for date, msgs in grouped_messages:
            history.append({
                'date': date.strftime('%Y-%m-%d'),
                'messages': [{'content': msg.content, 'is_user': msg.is_user, 'timestamp': msg.timestamp.strftime('%H:%M')} for msg in msgs]
            })
    
    return jsonify({'history': history})

def send_async_email(app, msg):
    """
    비동기적으로 이메일을 보내는 함수
    """
    with app.app_context():
        try:
            mail.send(msg)
            print("Email sent successfully")
        except Exception as e:
            print(f"Failed to send email: {str(e)}")

def send_password_reset_email(user):
    """
    비밀번호 재설정 이메일을 보내는 함수
    """
    token = user.reset_token
    msg = FlaskMessage(subject='Password Reset Request',
                       recipients=[user.email],
                       body=f'''To reset your password, visit the following link:
{url_for('reset_password_form', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
''')
    mail.send(msg)

@app.route('/request_reset', methods=['POST'])
def request_reset():
    """
    비밀번호 재설정 요청을 처리하는 라우트
    """
    try:
        email = request.json.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_reset_token()
            send_password_reset_email(user)
            return jsonify({"message": "Reset link sent to your email"})
        return jsonify({"message": "Email not found"}), 404
    except Exception as e:
        print(f"Error in request_reset: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@app.route('/reset_password/<token>', methods=['GET'])
def reset_password_form(token):
    """
    비밀번호 재설정 폼을 표시하는 라우트
    """
    user = User.query.filter_by(reset_token=token).first()
    if user and user.check_reset_token(token):
        return render_template('reset_password.html', token=token)
    return "Invalid or expired token", 400

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """
    비밀번호 재설정을 처리하는 라우트
    """
    token = request.json.get('token')
    new_password = request.json.get('new_password')
    user = User.query.filter_by(reset_token=token).first()
    if user and user.check_reset_token(token):
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        return jsonify({"message": "Password reset successful"})
    return jsonify({"message": "Invalid or expired token"}), 400

@app.route('/admin/backup_db')
@login_required
def backup_db():
    """
    데이터베이스 백업을 위한 관리자 라우트
    """
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized access"}), 403
    
    try:
        db_path = os.path.join(app.instance_path, 'users.db')
        
        if not os.path.exists(db_path):
            return jsonify({"error": "Database file not found"}), 404

        return send_file(db_path, as_attachment=True, download_name='users.db')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@click.command('create-admin')
@with_appcontext
def create_admin_command():
    """관리자 사용자 생성을 위한 CLI 명령"""
    username = click.prompt('Enter admin username', type=str)
    email = click.prompt('Enter admin email', type=str)
    password = click.prompt('Enter admin password', type=str, hide_input=True, confirmation_prompt=True)
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        if click.confirm('User with this email already exists. Do you want to make this user an admin?'):
            existing_user.is_admin = True
            db.session.commit()
            click.echo('User updated to admin successfully')
        else:
            click.echo('Admin user creation cancelled')
    else:
        admin_user = User(username=username, email=email, password=generate_password_hash(password), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        click.echo('Admin user created successfully')

app.cli.add_command(create_admin_command)

class UserConversationsView(BaseView):
    @expose('/')
    def index(self):
        users = User.query.all()
        return self.render('admin/user_conversations.html', users=users)
    
    @expose('/<int:user_id>')
    def user_conversations(self, user_id):
        user = User.query.get_or_404(user_id)
        conversations = Conversation.query.filter_by(user_id=user_id).all()
        
        all_messages = []
        for conv in conversations:
            all_messages.extend(conv.messages)
        
        all_messages.sort(key=attrgetter('timestamp'))
        
        grouped_messages = groupby(all_messages, key=lambda m: m.timestamp.date())
        
        grouped_conversations = {date: list(messages) for date, messages in grouped_messages}
        
        return self.render('admin/user_conversation_details.html', user=user, grouped_conversations=grouped_conversations)

admin.add_view(UserConversationsView(name='User Conversations', endpoint='user_conversations'))


# @app.route('/generate_report', methods=['POST'])
# @login_required
# def generate_report():
#     try:
#         user_messages = Message.query.filter_by(user_id=current_user.id, is_user=True).order_by(Message.timestamp.desc()).limit(10).all()
#         user_messages = [msg.content for msg in user_messages]
        
#         if not user_messages:
#             return jsonify({"success": False, "error": "No messages found for the user"}), 400
        
#         # OpenAI API를 사용하여 보고서 생성
#         response = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "You are a Korean language expert. Analyze the following messages and provide feedback. If there are grammatical errors or unnatural expressions, format your response as follows:\n\nIncorrect sentence: []\nReason: []\nRecommended native speaker sentence: []\n\nIf the sentence is perfect or particularly well-expressed, provide positive feedback such as 'This expression is excellent.' or 'This sentence is perfectly constructed.'. Always clearly distinguish between correct and incorrect sentences."},
#                 {"role": "user", "content": f"Analyze these messages:\n{' '.join(user_messages)}"}
#             ]
#         )
        
#         report_content = response.choices[0].message.content
        
#         # 새 보고서 저장
#         next_report_number = Report.query.filter_by(user_id=current_user.id).count() + 1
#         new_report = Report(user_id=current_user.id, content=report_content, report_number=next_report_number)
#         db.session.add(new_report)
#         db.session.commit()
        
#         return jsonify({"success": True, "report": report_content})
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"success": False, "error": str(e)}), 500

# @app.route('/get_reports', methods=['GET'])
# @login_required
# def get_reports():
#     reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.report_number.desc()).all()
#     return jsonify([{
#         "id": report.id,
#         "content": report.content,
#         "timestamp": report.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
#         "report_number": report.report_number
#     } for report in reports])

# @app.route('/get_vocabulary', methods=['GET'])
# @login_required
# def get_vocabulary():
#     user_messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).limit(100).all()
#     words = ' '.join([msg.content for msg in user_messages]).split()
#     word_counts = Counter(words)
#     vocabulary = [{"word": word, "count": count} for word, count in word_counts.most_common(50)]
#     return jsonify(vocabulary)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    report_number = db.Column(db.Integer, nullable=False)

    @classmethod
    def get_next_report_number(cls, user_id):
        last_report = cls.query.filter_by(user_id=user_id).order_by(cls.report_number.desc()).first()
        return (last_report.report_number + 1) if last_report else 1

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)