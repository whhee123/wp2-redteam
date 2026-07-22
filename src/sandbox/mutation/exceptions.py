"""Mutation pipeline errors."""


class MutationError(RuntimeError):
    pass


class MutationConfigError(MutationError):
    pass


class MutationProviderError(MutationError):
    pass


class MutationSchemaError(MutationError):
    pass


class MutationIntegrityError(MutationError):
    pass


class MutationStorageError(MutationError):
    pass


class MutationTargetError(MutationError):
    pass
