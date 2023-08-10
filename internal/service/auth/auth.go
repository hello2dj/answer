package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/answerdev/answer/internal/entity"
	"github.com/answerdev/answer/internal/schema"
	"github.com/answerdev/answer/internal/service/role"
	usercommon "github.com/answerdev/answer/internal/service/user_common"
	"github.com/answerdev/answer/pkg/token"
	"github.com/hasura/go-graphql-client"
	"github.com/segmentfault/pacman/log"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

// AuthRepo auth repository
type AuthRepo interface {
	GetUserCacheInfo(ctx context.Context, accessToken string) (userInfo *entity.UserCacheInfo, err error)
	SetUserCacheInfo(ctx context.Context, accessToken string, userInfo *entity.UserCacheInfo) error
	RemoveUserCacheInfo(ctx context.Context, accessToken string) (err error)
	SetUserStatus(ctx context.Context, userID string, userInfo *entity.UserCacheInfo) (err error)
	GetUserStatus(ctx context.Context, userID string) (userInfo *entity.UserCacheInfo, err error)
	RemoveUserStatus(ctx context.Context, userID string) (err error)
	GetAdminUserCacheInfo(ctx context.Context, accessToken string) (userInfo *entity.UserCacheInfo, err error)
	SetAdminUserCacheInfo(ctx context.Context, accessToken string, userInfo *entity.UserCacheInfo) error
	RemoveAdminUserCacheInfo(ctx context.Context, accessToken string) (err error)
	AddUserTokenMapping(ctx context.Context, userID, accessToken string) (err error)
	RemoveUserTokens(ctx context.Context, userID string)
}

// AuthService kit service
type AuthService struct {
	authRepo           AuthRepo
	userRepo           usercommon.UserRepo
	userRoleRelService *role.UserRoleRelService
	userCommonService  *usercommon.UserCommon
	g                  *singleflight.Group
}

// NewAuthService email service
func NewAuthService(
	authRepo AuthRepo,
	userRepo usercommon.UserRepo,
	userRoleRelService *role.UserRoleRelService,
	userCommonService *usercommon.UserCommon,
) *AuthService {
	return &AuthService{
		authRepo:           authRepo,
		userRepo:           userRepo,
		userRoleRelService: userRoleRelService,
		userCommonService:  userCommonService,
		g:                  &singleflight.Group{},
	}
}

func (as *AuthService) GetUserCacheInfo(ctx context.Context, accessToken string) (userInfo *entity.UserCacheInfo, err error) {
	userCacheInfo, err := as.authRepo.GetUserCacheInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	cacheInfo, _ := as.authRepo.GetUserStatus(ctx, userCacheInfo.UserID)
	if cacheInfo != nil {
		log.Debugf("user status updated: %+v", cacheInfo)
		userCacheInfo.UserStatus = cacheInfo.UserStatus
		userCacheInfo.EmailStatus = cacheInfo.EmailStatus
		userCacheInfo.RoleID = cacheInfo.RoleID
		// update current user cache info
		err := as.authRepo.SetUserCacheInfo(ctx, accessToken, userCacheInfo)
		if err != nil {
			return nil, err
		}
	}
	return userCacheInfo, nil
}

func (as *AuthService) getGQLClient(req *http.Request) *graphql.Client {
	return graphql.NewClient(fmt.Sprintf("%s/%s", os.Getenv("QY_ADDR"), "api/query"), http.DefaultClient).WithRequestModifier(func(nr *http.Request) {
		for k, v := range req.Header {
			if k == "Content-Type" {
				continue
			}
			nr.Header[k] = v
		}
	})
}

func (as *AuthService) GetQyUserInfo(ctx context.Context, req *http.Request) (*entity.UserCacheInfo, string, error) {
	cookie, err := req.Cookie("session")
	if err != nil {
		return nil, "", err
	}

	register := func() (interface{}, error) {
		client := as.getGQLClient(req)
		var (
			query struct {
				Me struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `graphql:"me"`
			}
		)

		if err := client.Query(ctx, &query, nil); err != nil {
			return nil, err
		}

		user, err := as.UserRegisterByEmailSilent(ctx, &schema.UserRegisterReq{
			Name:  query.Me.Name,
			Email: query.Me.Email,
			Pass:  "newcapec@123",
		})
		if err != nil {
			return nil, err
		}

		return &entity.UserCacheInfo{
			UserID:      user.ID,
			EmailStatus: user.MailStatus,
			UserStatus:  user.Status,
			RoleID:      role.RoleModeratorID,
		}, nil
	}

	v, err, _ := as.g.Do(cookie.Value, func() (interface{}, error) {
		return register()
	})
	if err != nil {
		return nil, "", err
	}
	return v.(*entity.UserCacheInfo), fmt.Sprintf("qy-%s", cookie.Value), nil
}

// UserRegisterByEmailSilent user register
func (as *AuthService) UserRegisterByEmailSilent(ctx context.Context, registerUserInfo *schema.UserRegisterReq) (user *entity.User, err error) {
	user, has, err := as.userRepo.GetByEmail(ctx, registerUserInfo.Email)
	if err != nil {
		return nil, err
	}
	if has {
		return user, nil
	}

	userInfo := &entity.User{}
	userInfo.EMail = registerUserInfo.Email
	userInfo.DisplayName = registerUserInfo.Name
	userInfo.Pass, err = encryptPassword(ctx, registerUserInfo.Pass)
	if err != nil {
		return nil, err
	}
	userInfo.Username, err = as.userCommonService.MakeUsername(ctx, registerUserInfo.Name)
	if err != nil {
		return nil, err
	}
	userInfo.IPInfo = registerUserInfo.IP
	userInfo.MailStatus = entity.EmailStatusAvailable
	userInfo.Status = entity.UserStatusAvailable
	userInfo.LastLoginDate = time.Now()

	if err = as.userRepo.AddUser(ctx, userInfo); err != nil {
		return
	}

	time.Sleep(100 * time.Millisecond)
	return user, as.userRoleRelService.SaveUserRole(ctx, userInfo.ID, role.RoleModeratorID)
}

func encryptPassword(ctx context.Context, Pass string) (string, error) {
	hashPwd, err := bcrypt.GenerateFromPassword([]byte(Pass), bcrypt.DefaultCost)
	// This encrypted string can be saved to the database and can be used as password matching verification
	return string(hashPwd), err
}

func (as *AuthService) SetUserCacheInfo(ctx context.Context, userInfo *entity.UserCacheInfo) (accessToken string, err error) {
	accessToken = token.GenerateToken()
	err = as.authRepo.SetUserCacheInfo(ctx, accessToken, userInfo)
	return accessToken, err
}

func (as *AuthService) SetUserStatus(ctx context.Context, userInfo *entity.UserCacheInfo) (err error) {
	return as.authRepo.SetUserStatus(ctx, userInfo.UserID, userInfo)
}

func (as *AuthService) UpdateUserCacheInfo(ctx context.Context, token string, userInfo *entity.UserCacheInfo) (err error) {
	err = as.authRepo.SetUserCacheInfo(ctx, token, userInfo)
	if err != nil {
		return err
	}
	if err := as.authRepo.RemoveUserStatus(ctx, userInfo.UserID); err != nil {
		log.Error(err)
	}
	return
}

func (as *AuthService) RemoveUserCacheInfo(ctx context.Context, accessToken string) (err error) {
	return as.authRepo.RemoveUserCacheInfo(ctx, accessToken)
}

// AddUserTokenMapping add user token mapping
func (as *AuthService) AddUserTokenMapping(ctx context.Context, userID, accessToken string) (err error) {
	return as.authRepo.AddUserTokenMapping(ctx, userID, accessToken)
}

// RemoveUserTokens Log out all users under this user id
func (as *AuthService) RemoveUserTokens(ctx context.Context, userID string) {
	as.authRepo.RemoveUserTokens(ctx, userID)
}

//Admin

func (as *AuthService) GetAdminUserCacheInfo(ctx context.Context, accessToken string) (userInfo *entity.UserCacheInfo, err error) {
	return as.authRepo.GetAdminUserCacheInfo(ctx, accessToken)
}

func (as *AuthService) SetAdminUserCacheInfo(ctx context.Context, accessToken string, userInfo *entity.UserCacheInfo) (err error) {
	err = as.authRepo.SetAdminUserCacheInfo(ctx, accessToken, userInfo)
	return err
}

func (as *AuthService) RemoveAdminUserCacheInfo(ctx context.Context, accessToken string) (err error) {
	return as.authRepo.RemoveAdminUserCacheInfo(ctx, accessToken)
}
