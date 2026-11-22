use bitflags::bitflags;

bitflags! {
	/// Institution permission bits. Combine flags with `|` and pass `.bits()`
	/// to a requirement with `PermissionScope::Institution`.
	///
	/// ```
	/// use blokmap_auth::authorization::InstitutionPermissions as Permissions;
	/// let required = Permissions::ManageMembers | Permissions::ManageRoles;
	/// let wire_value: i64 = required.bits();
	/// ```
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct InstitutionPermissions: i64 {
		/// Institution admin, member can do everything
		const Administrator = 1 << 0;
		/// Member can manage settings for the institution
		const ManageSettings = 1 << 1;
		/// Member can manage institution members
		/// - add members
		/// - update member roles
		/// - remove members
		const ManageMembers = 1 << 2;
		/// Member can manage institution roles
		/// - create roles
		/// - update roles
		/// - delete roles
		const ManageRoles = 1 << 3;
		/// Member can manage profiles of the institution
		const ManageProfiles = 1 << 4;
		/// Member can create locations for this institution
		const CreateLocations = 1 << 5;
		/// Member can update and delete locations for this institution
		const ManageLocations = 1 << 6;
	}
}

bitflags! {
	/// Location permission bits. Pair with `PermissionScope::Location` and
	/// pass the resulting `i64` as an authorization requirement's `permission`.
	///
	/// ```
	/// use blokmap_auth::authorization::LocationPermissions;
	/// let permission = LocationPermissions::ManageSettings.bits();
	/// ```
	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub struct LocationPermissions: i64 {
		/// Admin privileges, member can do everything
		const Administrator = 1 << 0;
		/// Member can manage opening times for this location:
		/// - create opening times
		/// - update opening times
		/// - delete opening times
		const ManageOpeningTimes = 1 << 1;
		/// Member can manage location members
		/// - add members
		/// - update member roles
		/// - remove members
		const ManageMembers = 1 << 2;
		/// Member can manage location roles
		/// - create roles
		/// - update roles
		/// - delete roles
		const ManageRoles = 1 << 3;
		/// Member can manage reservations for this location
		/// - update reservation state
		const ManageReservations = 1 << 4;
		/// Member can manage the settings for this location
		/// - update overview (name, excerpt, description)
		/// - update location address
		/// - update location images
		/// - update location tags
		/// - update location images
		/// - update location settings
		const ManageSettings = 1 << 5;
		/// Member can manage QR code for this location
		/// - regenerate QR code
		const GenerateQrCode = 1 << 6;
		/// Member can cycle (invalidate) all QR codes for this location
		/// - regenerate all QR codes for this location
		const CycleQrCodes = 1 << 7;
	}
}
