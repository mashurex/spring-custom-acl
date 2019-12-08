package com.ashurex.springcustomacl.security.acls.domain;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.acls.domain.AbstractPermission;
import org.springframework.security.acls.model.Permission;

/**
 * Custom named permission implementation of Spring {@link Permission}.
 *
 * @author Mustafa Ashurex
 */
public class CustomPermission extends AbstractPermission {
	public static final char READ_CODE = 'R';
	public static final char WRITE_CODE = 'W';
	public static final char CREATE_CODE = 'C';
	public static final char EDIT_CODE = 'E';
	public static final char ADMIN_CODE = 'A';


	public static final Permission TX_READ = new CustomPermission("00000000000000000000000000000001", READ_CODE);
	public static final Permission TX_CREATE = new CustomPermission("00000000000000000000000000000010", CREATE_CODE);
	public static final Permission TX_EDIT = new CustomPermission("00000000000000000000000000000100", EDIT_CODE);
	public static final Permission TX_ADMIN = new CustomPermission("00000000000000000000000000001000", ADMIN_CODE);
	public static final Permission POS_READ = new CustomPermission("00000000000000000000000000010000", READ_CODE);
	public static final Permission POS_ADMIN = new CustomPermission("00000000000000000000000000100000", ADMIN_CODE);
	public static final Permission CORP_ACT_READ = new CustomPermission("00000000000000000000000001000000", READ_CODE);
	public static final Permission CORP_ACT_CREATE = new CustomPermission("00000000000000000000000010000000",
																		  CREATE_CODE);
	public static final Permission CORP_ACT_EDIT = new CustomPermission("00000000000000000000000100000000", EDIT_CODE);
	public static final Permission CORP_ACT_ADMIN = new CustomPermission("00000000000000000000001000000000",
																		 ADMIN_CODE);
	public static final Permission CASH_MGR_READ = new CustomPermission("00000000000000000000010000000000", READ_CODE);
	public static final Permission CASH_MGR_ADMIN = new CustomPermission("00000000000000000000100000000000",
																		 ADMIN_CODE);
	public static final Permission FILE_MGR_READ = new CustomPermission("00000000000000000001000000000000", READ_CODE);
	public static final Permission FILE_MGR_ADMIN = new CustomPermission("00000000000000000010000000000000",
																		 ADMIN_CODE);
	public static final Permission REC_TOOLS_READ = new CustomPermission("00000000000000000100000000000000", READ_CODE);
	public static final Permission REC_TOOLS_ADMIN = new CustomPermission("00000000000000001000000000000000",
																		  ADMIN_CODE);
	public static final Permission SECURITIES_ADMIN = new CustomPermission("00000000000000010000000000000000",
																		   ADMIN_CODE);
	public static final Permission PRICES_ADMIN = new CustomPermission("00000000000000100000000000000000", ADMIN_CODE);
	public static final Permission FEE_SCHEDULE_READ = new CustomPermission("00000000000001000000000000000000",
																			READ_CODE);
	public static final Permission FEE_SCHEDULE_ADMIN = new CustomPermission("00000000000010000000000000000000",
																			 ADMIN_CODE);
	public static final Permission P_L_READ = new CustomPermission("00000000000100000000000000000000", READ_CODE);
	public static final Permission P_L_ADMIN = new CustomPermission("00000000001000000000000000000000", ADMIN_CODE);
	public static final Permission SYS_REP_READ = new CustomPermission("00000000010000000000000000000000", READ_CODE);
	public static final Permission SYS_REP_ADMIN = new CustomPermission("00000000100000000000000000000000", ADMIN_CODE);
	public static final Permission EXTERN_REP_READ = new CustomPermission("00000001000000000000000000000000",
																		  READ_CODE);
	public static final Permission EXTERN_REP_ADMIN = new CustomPermission("00000010000000000000000000000000",
																		   ADMIN_CODE);
	public static final Permission CUST_PERM_1 = new CustomPermission("00000100000000000000000000000000", 'X');
	public static final Permission CUST_PERM_2 = new CustomPermission("00001000000000000000000000000000", 'X');
	public static final Permission CUST_PERM_3 = new CustomPermission("00010000000000000000000000000000", 'X');
	public static final Permission CUST_PERM_4 = new CustomPermission("00100000000000000000000000000000", 'X');
	public static final Permission CLIENT_ADMIN = new CustomPermission("01000000000000000000000000000000", ADMIN_CODE);

	private static final Map<String, Permission> PERMISSION_MAP;

	static {
		Map<String, Permission> p = new HashMap<>();
		p.put("TX_READ", TX_READ);
		p.put("TX_CREATE", TX_CREATE);
		p.put("TX_EDIT", TX_EDIT);
		p.put("TX_ADMIN", TX_ADMIN);
		p.put("POS_READ", POS_READ);
		p.put("POS_ADMIN", POS_ADMIN);
		p.put("CORP_ACT_READ", CORP_ACT_READ);
		p.put("CORP_ACT_CREATE", CORP_ACT_CREATE);
		p.put("CORP_ACT_EDIT", CORP_ACT_EDIT);
		p.put("CORP_ACT_ADMIN", CORP_ACT_ADMIN);
		p.put("CASH_MGR_READ", CASH_MGR_READ);
		p.put("FILE_MGR_READ", FILE_MGR_READ);
		p.put("FILE_MGR_ADMIN", FILE_MGR_ADMIN);
		p.put("REC_TOOLS_READ", REC_TOOLS_READ);
		p.put("REC_TOOLS_ADMIN", REC_TOOLS_ADMIN);
		p.put("SECURITIES_ADMIN", SECURITIES_ADMIN);
		p.put("PRICES_ADMIN", PRICES_ADMIN);
		p.put("FEE_SCHEDULE_READ", FEE_SCHEDULE_READ);
		p.put("FEE_SCHEDULE_ADMIN", FEE_SCHEDULE_ADMIN);
		p.put("P_L_READ", P_L_READ);
		p.put("P_L_ADMIN", P_L_ADMIN);
		p.put("SYS_REP_READ", SYS_REP_READ);
		p.put("SYS_REP_ADMIN", SYS_REP_ADMIN);
		p.put("EXTERN_REP_READ", EXTERN_REP_READ);
		p.put("CUST_PERM_1", CUST_PERM_1);
		p.put("CUST_PERM_2", CUST_PERM_2);
		p.put("CUST_PERM_3", CUST_PERM_3);
		p.put("CUST_PERM_4", CUST_PERM_4);
		p.put("CLIENT_ADMIN", CLIENT_ADMIN);

		PERMISSION_MAP = Collections.unmodifiableMap(p);
	}

	public CustomPermission(int mask) {
		super(mask);
	}

	public CustomPermission(int mask, char code) {
		super(mask, code);
	}

	public CustomPermission(String mask, char code) {
		this(Integer.parseInt(mask, 2), code);
	}

	public static Map<String, Permission> getPermissionsMap() {
		return PERMISSION_MAP;
	}
}
