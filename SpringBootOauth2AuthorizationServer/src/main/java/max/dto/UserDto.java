package max.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private Long id;

    private String firstName;

    private String lastName;

    private String middleName;

    private String login;

    private String password;

    private String keycloakId;

    private String eMailAddress;

    private Long organization;

    private Integer status;

    private Long role;

    private String systemName;

    private String sessionIdAuth;

    private Date dateCreation;

    private Date dateUpdate;

    private Date dateSessionAuth;

    private Long userCreated;

    private Long userUpdate;

    private Boolean isArchive;

}
