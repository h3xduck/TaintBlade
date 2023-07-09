/****************************************************************************
** Meta object code from reading C++ file 'TracedProcessDrawer.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/process/TracedProcessDrawer.h"
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'TracedProcessDrawer.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS = QtMocHelpers::stringData(
    "TracedProcessDrawer",
    "sendRequestShowTracedProcessWidget",
    "",
    "pid",
    "dll",
    "timestamp"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS_t {
    uint offsetsAndSizes[12];
    char stringdata0[20];
    char stringdata1[35];
    char stringdata2[1];
    char stringdata3[4];
    char stringdata4[4];
    char stringdata5[10];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS_t qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS = {
    {
        QT_MOC_LITERAL(0, 19),  // "TracedProcessDrawer"
        QT_MOC_LITERAL(20, 34),  // "sendRequestShowTracedProcessW..."
        QT_MOC_LITERAL(55, 0),  // ""
        QT_MOC_LITERAL(56, 3),  // "pid"
        QT_MOC_LITERAL(60, 3),  // "dll"
        QT_MOC_LITERAL(64, 9)   // "timestamp"
    },
    "TracedProcessDrawer",
    "sendRequestShowTracedProcessWidget",
    "",
    "pid",
    "dll",
    "timestamp"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSTracedProcessDrawerENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       1,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    3,   20,    2, 0x06,    1 /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,    3,    4,    5,

       0        // eod
};

Q_CONSTINIT const QMetaObject TracedProcessDrawer::staticMetaObject = { {
    QMetaObject::SuperData::link<QThread::staticMetaObject>(),
    qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSTracedProcessDrawerENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<TracedProcessDrawer, std::true_type>,
        // method 'sendRequestShowTracedProcessWidget'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>,
        QtPrivate::TypeAndForceComplete<QString, std::false_type>
    >,
    nullptr
} };

void TracedProcessDrawer::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<TracedProcessDrawer *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->sendRequestShowTracedProcessWidget((*reinterpret_cast< std::add_pointer_t<QString>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[3]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TracedProcessDrawer::*)(QString , QString , QString );
            if (_t _q_method = &TracedProcessDrawer::sendRequestShowTracedProcessWidget; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
    }
}

const QMetaObject *TracedProcessDrawer::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TracedProcessDrawer::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSTracedProcessDrawerENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int TracedProcessDrawer::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 1)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 1;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 1)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 1;
    }
    return _id;
}

// SIGNAL 0
void TracedProcessDrawer::sendRequestShowTracedProcessWidget(QString _t1, QString _t2, QString _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
